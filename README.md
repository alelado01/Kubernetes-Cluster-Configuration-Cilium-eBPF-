## Set up

This document analyzes the full installation procedure used in the TER project: a bare-metal two-node cluster (`master` as master, `worker` as worker) running K3s on openSUSE Leap 15.6, with Intel X710 10G NICs (`eth0` on master, `eth1`/`eth0` on worker) for the data plane and Broadcom management interfaces (`em2`) for SSH.

---

### Standard Installation

#### 1. Hardware Inventory and Pre-flight Checks

| Node   | Role   | Data NIC         | Data IP        | Mgmt NIC | Mgmt IP           |
|--------|--------|------------------|----------------|----------|-------------------|
| master | master | eth0 (Intel X710)| 10.4.100.1/8   | em2      | 134.59.131.204    |
| worker | worker | eth1 (Intel X710)| 10.2.100.1/8   | em2      | 134.59.131.202    |


Verify physical connectivity before starting:
```bash
# From master, verify the data-plane link to worker is up
ping -c 3 -I eth0 10.2.100.1

# From master, verify MAC resolution (ARP must not be STALE or INCOMPLETE)
ip neigh show 10.2.100.1 dev eth0
```

---

#### 2. Hardware Hardening (LRO/GRO)

**Before** starting any CNI, disable hardware offloading on both nodes. Failure to do this before Cilium attaches XDP causes a hard kernel lockup (see [Error E2](#errors-and-solutions)).

```bash
# On both master and worker
sudo ethtool -K eth0 lro off gro off
```

> Never run `ethtool` flags that modify hardware state (queue count, offloads, ring buffer) **while Cilium is running**. Doing so forces a driver reset that removes all attached BPF programs, potentially causing a crash loop.

---

#### 3. Full Node Reset / CNI Rotation

When switching from one CNI to another, a full cleanup is required on every node. Leftover CNI configuration files, virtual interfaces, and BPF state from the old CNI will corrupt the new installation.

```bash
# ── On the MASTER ────────────────────────────────────────────────────────
sudo systemctl stop k3s
sudo /usr/local/bin/k3s-uninstall.sh

# ── On each WORKER ───────────────────────────────────────────────────────
sudo systemctl stop k3s-agent
sudo /usr/local/bin/k3s-agent-uninstall.sh

# ── On BOTH nodes ────────────────────────────────────────────────────────
# Remove virtual interfaces left by the old CNI
sudo ip link delete cni0         2>/dev/null || true
sudo ip link delete flannel.1    2>/dev/null || true
sudo ip link delete antrea-gw0   2>/dev/null || true
sudo ip link delete cilium_vxlan 2>/dev/null || true

# Remove CNI configuration and state
sudo rm -rf /etc/cni/net.d/*
sudo rm -rf /var/lib/cni/

# Remove residual BPF state
sudo rm -rf /sys/fs/bpf/*

# Detach any residual XDP / TC programs from the physical NIC
sudo ip link set dev eth0 xdp off       2>/dev/null || true
sudo tc qdisc del dev eth0 clsact       2>/dev/null || true
```

> **Note (orphaned BPF links):** If a Cilium pod crashed mid-operation, the kernel may retain BPF Link anchors that `ip link set xdp off` cannot remove (see [Error E1](#errors-and-solutions)). Use `bpftool` to force-detach them:
> ```bash
> sudo bpftool net list dev eth0          # list all attached programs with IDs
> sudo bpftool link detach id <ID>        # repeat for each link ID
> ```

---

#### 4. K3s Installation

##### Master node

```bash
curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="server \
  --node-ip=10.4.100.1 \
  --node-external-ip=134.59.131.204 \
  --flannel-backend=none \
  --disable-network-policy \
  --write-kubeconfig-mode 644" sh -s -

# Export kubeconfig (add to ~/.bashrc for persistence)
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

# Retrieve the join token for worker nodes
sudo cat /var/lib/rancher/k3s/server/node-token
```

##### Worker node

```bash
curl -sfL https://get.k3s.io | \
  K3S_URL=https://10.4.100.1:6443 \
  K3S_TOKEN=<TOKEN_FROM_MASTER> \
  INSTALL_K3S_EXEC="agent --node-ip=10.2.100.1" sh -
```

After installation, `kubectl get nodes` will show all nodes in `NotReady` — this is expected because no CNI is installed yet.

---

#### 5. CNI Installation

##### Flannel

Flannel is the simplest CNI for K3s. It uses VXLAN encapsulation by default and requires no special hardware configuration.

```bash
kubectl apply -f https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml
```

Wait for pods to reach `Running`:
```bash
kubectl get pods -n kube-flannel -w
```

##### Antrea

Antrea uses Open vSwitch (OVS) as its datapath. It provides better performance at high connection counts than the standard iptables stack, and does not require any hardware queue tuning.

```bash
kubectl apply -f https://github.com/antrea-io/antrea/releases/latest/download/antrea.yml
```

Wait for pods to reach `Running`:
```bash
kubectl get pods -n kube-system -l app=antrea -w
```

##### Cilium (VXLAN + XDP Native)

Cilium requires more configuration steps due to the hardware constraints of the Intel X710 driver (`i40e`).

###### Step 1 — Add the Helm repository

```bash
helm repo add cilium https://helm.cilium.io/
helm repo update
```

###### Step 2 — Base install

The following configuration installs Cilium with VXLAN tunneling, MTU=1400 (mandatory for VXLAN + XDP, see [Error E3](#errors-and-solutions)), and XDP Native acceleration enabled. The `devices` field is left empty here because the two nodes use different interface names — per-node overrides are handled in Step 3.

```bash
helm install cilium cilium/cilium \
  --namespace kube-system \
  --set k8sServiceHost=10.4.100.1 \
  --set k8sServicePort=6443 \
  --set routingMode=tunnel \
  --set tunnelProtocol=vxlan \
  --set mtu=1400 \
  --set bpf.masquerade=true \
  --set loadBalancer.acceleration=native \
  --set nodePort.acceleration=native \
  --set bpf.legacyBPFLink=true \
  --set devices='' \
  --set operator.replicas=1 \
  --set operator.nodeSelector."kubernetes\.io/hostname"=master \
  --set operator.hostNetwork=true
```

> **IPAM bootstrap catch-22 (Error E5):** If the Cilium operator is scheduled on the worker node, it cannot reach the master's API server via VXLAN because VXLAN itself is not yet up. `operator.nodeSelector` and `operator.hostNetwork=true` force the operator to the master and to use the physical management network, breaking the deadlock.

###### Step 3 — Per-node device override via CiliumNodeConfig CRD

Because `master` uses `eth0` and `worker` originally uses `eth1`, and if `master` also has a second Intel port `eth1` that is **not connected**, a global `--set devices=eth0,eth1` will crash the node that encounters the unconnected interface (see [Error E6](#errors-and-solutions)). The solution is to use the `CiliumNodeConfig` CRD to apply per-node device settings.

Label the nodes:
```bash
kubectl label nodes master hw-profile=master-layout
kubectl label nodes worker hw-profile=worker-layout
```

Create the file `node-config.yaml`:
```yaml
apiVersion: cilium.io/v2
kind: CiliumNodeConfig
metadata:
  namespace: kube-system
  name: master-device-override
spec:
  nodeSelector:
    matchLabels:
      hw-profile: master-layout
  defaults:
    devices: "eth0"
---
apiVersion: cilium.io/v2
kind: CiliumNodeConfig
metadata:
  namespace: kube-system
  name: worker-device-override
spec:
  nodeSelector:
    matchLabels:
      hw-profile: worker-layout
  defaults:
    devices: "eth0"
```

Apply and restart the Cilium agents:
```bash
kubectl apply -f node-config.yaml
kubectl delete pod -n kube-system -l k8s-app=cilium
```

###### Step 4 — Post-install validation

```bash
# Check overall Cilium status
kubectl exec -n kube-system ds/cilium -- cilium status

# Check inter-node health
kubectl exec -n kube-system ds/cilium -- cilium-health status

# Verify XDP is attached to the physical NIC (look for "prog/xdp id <N>")
ip link show eth0

# Verify the VXLAN interface MTU is 1400 (not 1500 — see Error E4)
ip -d link show cilium_vxlan | grep mtu
```

If `cilium_vxlan` still shows `mtu 1500` after a `helm upgrade --set mtu=1400`:
```bash
# Delete the stale interface; it will be recreated at the correct MTU on pod restart
sudo ip link delete cilium_vxlan
kubectl delete pod -n kube-system -l k8s-app=cilium
```

---

#### 6. Errors and Solutions

The following errors were encountered during the deployment of this cluster. Each entry includes the symptom, root cause, and working fix.

---

**E1 — XDP BPF Link cannot be detached with `ip link set xdp off`**
- **Error:** `Error: Can't replace active BPF XDP link`
- **Cause:** Cilium 1.19 uses kernel BPF Link anchors instead of legacy XDP attachment. `ip link set xdp off` only removes legacy attachments.
- **Fix:**
  ```bash
  sudo bpftool net list dev eth0          # find all attached programs and their link IDs
  sudo bpftool link detach id <ID>        # repeat for each XDP and TCX link ID
  ```

---

**E2 — Orphaned TCX links block ALL traffic after a Cilium pod crash**
- **Error:** `ip neigh show` returns empty (ARP blocked); `ping` reports 100% loss even though the physical link is UP.
- **Cause:** When a Cilium pod crashes mid-operation, it leaves `tcx/ingress cil_from_netdev` and `tcx/egress cil_to_netdev` BPF links attached to the NIC. These links intercept and drop every packet, including ARP.
- **Fix:**
  ```bash
  sudo bpftool net list dev eth0          # identify TCX link IDs (e.g. 103, 155, 106, 156)
  sudo bpftool link detach id 103
  sudo bpftool link detach id 155
  sudo bpftool link detach id 106
  sudo bpftool link detach id 156
  # After detaching, verify ARP recovers:
  arping -c 3 -I eth0 10.2.100.1
  ```

> **If `bpftool` is not enough:** A hard lockup with no SSH access requires a physical reboot of the affected machine.

---

**E3 — MTU mismatch causes kernel panic (VXLAN + XDP)**
- **Cause:** Pod MTU=1500 + VXLAN header (50 bytes) = 1550-byte packet. The Intel NIC configured at MTU 1500 silently drops the oversized packet in the XDP path, and under load this triggers a hard lockup / kernel panic.
- **Fix:** Set `--set mtu=1400` during Cilium installation. Physical NIC stays at 1500; only the pod and VXLAN interface are lowered.
  ```bash
  helm install cilium cilium/cilium ... --set mtu=1400
  ```

---

**E4 — `cilium_vxlan` stays at MTU 1500 after `helm upgrade --set mtu=1400`**
- **Cause:** Cilium does not update the MTU of an already-existing `cilium_vxlan` interface at runtime.
- **Fix:** Manually delete the stale interface; it is recreated with the correct MTU when the Cilium pod restarts.
  ```bash
  sudo ip link delete cilium_vxlan
  kubectl delete pod -n kube-system -l k8s-app=cilium
  ip -d link show cilium_vxlan | grep mtu   # must show 1400
  ```

---

**E5 — IPAM operator deadlock (operator scheduled on worker node)**
- **Cause:** The Cilium operator is scheduled on the worker node. It needs the VXLAN tunnel to reach the master's API server for IPAM. But the VXLAN tunnel cannot come up without the operator completing IPAM.
- **Symptom:** Cilium agents on both nodes stuck in `Init` indefinitely; no pods get IP addresses.
- **Fix:**
  ```bash
  helm upgrade cilium cilium/cilium --reuse-values \
    --set operator.nodeSelector."kubernetes\.io/hostname"=master \
    --set operator.hostNetwork=true
  ```

---

**E6 — Master has an unconnected second Intel port (`eth1`)**
- **Cause:** The master server has a multi-port Intel X710 card. `eth1` is a second port with no cable attached (NO-CARRIER). Setting `--set devices='{eth0,eth1}'` globally causes Cilium to attempt to attach XDP to `eth1` on master, which fails with a hard crash.
- **Fix:** Use the `CiliumNodeConfig` CRD to specify `devices: "eth0"` for master and `devices: "eth0"` (or the original name before rename) for worker independently (see Step 3 above).

---

**E7 — `helm uninstall` leaves `cilium-secrets` namespace stuck in `Terminating`**
- **Symptom:** After `helm uninstall cilium`, `kubectl get ns` shows `cilium-secrets` stuck in `Terminating` indefinitely. Any subsequent `helm install` fails with `unable to create new content in namespace cilium-secrets because it is being terminated`.
- **Fix:** Remove the namespace finalizers manually:
  ```bash
  kubectl patch namespace cilium-secrets \
    -p '{"spec":{"finalizers":[]}}' --type='merge'

  cat <<EOF | kubectl replace --raw /api/v1/namespaces/cilium-secrets/finalize -f -
  {"apiVersion":"v1","kind":"Namespace","metadata":{"name":"cilium-secrets"},"spec":{"finalizers":[]}}
  EOF
  ```

---

**E8 — Helm "cannot re-use a name that is still in use"**
- **Cause:** A previous `helm uninstall` was interrupted, leaving a Helm state secret in `kube-system` that marks the release as still deployed.
- **Fix:**
  ```bash
  kubectl delete secret -n kube-system -l owner=helm,name=cilium
  ```

---

**E9 — `ethtool -L eth0 combined 1` or any hardware-modifying ethtool command removes XDP**
- **Cause:** Modifying NIC queue count (or any other hardware parameter via `ethtool`) forces the `i40e` driver to reset, which detaches all BPF programs.
- **Rule:** **Never run `ethtool -L`, `ethtool -G`, `ethtool -K` (for offloads), or any hardware-modifying flag while Cilium is running.** Run these commands before `helm install`, then do not touch the NIC again.

---

**E10 — `--devices` with MAC addresses is silently ignored**
- **Cause:** Cilium 1.19 `--devices` only accepts interface name patterns or CIDRs. MAC address syntax (e.g. `--set devices='40:a6:b7:41:09:60'`) is silently ignored.
- **Symptom:** Cilium starts, reports XDP acceleration enabled, but `ip link show eth0` shows no `prog/xdp` ID; only virtual interfaces (`cilium_vxlan`, `cilium_host`) get BPF programs attached.
- **Fix:** Use interface names (`eth0`) or the `CiliumNodeConfig` CRD approach for per-node overrides.

---

**E11 — `--devices` with a CIDR filter fails silently on reboot**
- **Cause:** The CIDR filter only matches if the interface already has the specified IP address at the exact moment the Cilium pod starts. On reboot, interfaces may come up before the IP is configured, causing the match to fail silently.
- **Symptom:** Same as E10 — no `prog/xdp` on the physical NIC.
- **Fix:** Use explicit interface names or the `CiliumNodeConfig` CRD.

---

**E12 — `k8sServiceHost=127.0.0.1` breaks Cilium init containers on worker**
- **Cause:** The default `k8sServiceHost=127.0.0.1` is correct for the master but cannot be reached from the worker node.
- **Fix:** Always set `--set k8sServiceHost=<master-data-plane-IP>` (master's data-plane IP) in the helm command.

---

**E13 — `unmanaged-pod-watcher-interval` type mismatch (Cilium v1.16+)**
- **Error:** `invalid value "15s" for --unmanaged-pod-watcher-interval: expected int64`
- **Cause:** Cilium changed the type of this field from a duration string to an integer in v1.16. Old ConfigMap entries with string values like `"15s"` crash the agent.
- **Fix:**
  ```bash
  kubectl patch configmap cilium-config -n kube-system \
    --type=json \
    -p='[{"op":"remove","path":"/data/unmanaged-pod-watcher-interval"}]'
  ```

---

**E14 — Pods stuck in `ContainerCreating` after CNI switch (residual CNI config)**
- **Cause:** Old `.conflist` files in `/etc/cni/net.d/` from the previous CNI are still present and conflict with the new CNI's network configuration.
- **Fix:**
  ```bash
  sudo rm /etc/cni/net.d/*<old-cni-name>*
  sudo systemctl restart k3s        # on master
  sudo systemctl restart k3s-agent  # on worker
  ```

---

**E15 — Broadcom NIC hard lockup from XDP (master management interface)**
- **Cause:** A global `--set devices='{eth0,eth1}'` accidentally targeted the Broadcom management NIC (`tg3` driver) instead of the intended second Intel port. The `tg3` driver has no XDP support; injecting a BPF XDP program causes an immediate kernel hard lockup.
- **Fix:** Never include Broadcom interfaces in the `devices` list. Use only Intel interfaces. Verify interface drivers with `ethtool -i <iface>` before specifying them.

---

**E16 — `helm upgrade --set loadBalancer.acceleration=generic` crashes agent**
- **Error:** `Invalid value for --node-port-acceleration: generic`
- **Cause:** Cilium 1.19 accepts only `native` or `disabled` for `loadBalancer.acceleration` / `nodePort.acceleration`. The value `generic` is not valid in this version.
- **Fix:** Use `--set loadBalancer.acceleration=native` for XDP hardware acceleration or `--set loadBalancer.acceleration=disabled` to fall back to TC-eBPF (no XDP).

---

**E17 — `helm upgrade --set tunnel=disabled` fails with deprecation error**
- **Error:** `tunnel was deprecated in v1.14 and has been removed in v1.15`
- **Fix:** Use `--set routingMode=native` instead of `--set tunnel=disabled` in Cilium 1.15+.

---

**E18 — Subnet mask `/8` on the worker's data interface routes all pod traffic to the physical NIC**
- **Cause:** `ip addr add 10.2.100.1/8 dev eth1` means the route `10.0.0.0/8 via eth1` is installed. Since pod CIDRs (e.g. `10.0.0.0/16`) are within `10.0.0.0/8`, all pod-to-pod traffic is routed out of the physical NIC instead of through the VXLAN tunnel, causing 100% packet loss between nodes.
- **Fix:** Use a `/16` mask:
  ```bash
  sudo ip addr flush dev eth1
  sudo ip addr add 10.2.100.1/16 dev eth1
  ```

---

### Modified Cilium Installation

This section covers deploying **Killian's modified Cilium build**, which adds native VXLAN XDP acceleration as a first-class feature via a new `vxlanAcceleration` Helm block. Unlike standard Cilium (which requires the `CiliumNodeConfig` CRD workaround to attach XDP to the physical NIC), this patched build exposes dedicated acceleration controls directly in the values file.

The workflow has three phases:
1. Build the custom Docker images locally
2. Export the images as archives and import them on every cluster node via `k3s ctr`
3. Deploy with `helm upgrade --install` using the adapted values file

---

#### Prerequisites

- Docker (or compatible builder) installed on your local machine
- The modified Cilium source tree checked out locally
- SSH access to both nodes via their management IPs (`134.59.131.204` for master, `134.59.131.202` for worker)
- K3s already installed and running (see [Standard Installation](#standard-installation))

> **Import before deploy:** Because `pullPolicy: Never` is used, the container runtime will **never** attempt to pull the image from the internet. If the image is not already imported on a node before the Cilium pod is scheduled there, the pod fails immediately with `ErrImageNeverPull`. Always run the import step on **all nodes** before applying Helm.

---

#### Step 1 — Build and distribute the custom image

The script below is adapted from Killian's original `build-push-save.sh`. The Grid5000 intermediate hop (`nancy.g5k`) is replaced with direct SCP to the cluster management IPs. The container import uses `k3s ctr` (K3s bundles its own containerd instance; the system `ctr` binary, if present, targets a different socket and will not make images visible to the scheduler).

Save as `build-push-save.sh` and make executable with `chmod +x build-push-save.sh`.

```bash
#!/usr/bin/env bash
set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
MASTER_IP="134.59.131.204"   # management IP of the master node
WORKER_IP="134.59.131.202"   # management IP of the worker node
SSH_USER="<your-ssh-user>"   # SSH username on both nodes
IMAGE_TAG="vxlan-xdp-dev"
CILIUM_IMAGE="quay.io/cilium/cilium:${IMAGE_TAG}"
OPERATOR_IMAGE="quay.io/cilium/operator-generic:${IMAGE_TAG}"
CILIUM_ARCHIVE="cilium-${IMAGE_TAG}.tar.gz"
OPERATOR_ARCHIVE="cilium-operator-${IMAGE_TAG}.tar.gz"
# ─────────────────────────────────────────────────────────────────────────────

# Parse --no-build flag
BUILD_IMAGE=true
for arg in "$@"; do
    [[ "$arg" == "--no-build" ]] && BUILD_IMAGE=false
done

# ── 1. Build ─────────────────────────────────────────────────────────────────
if [[ "$BUILD_IMAGE" == "true" ]]; then
    if [[ "$OSTYPE" == "darwin"* ]]; then
        NPROC=$(sysctl -n hw.ncpu)
    else
        NPROC=$(nproc)
    fi

    export DOCKER_DEFAULT_PLATFORM=linux/amd64

    echo "==> Building cilium image..."
    make docker-cilium-image \
        DOCKER_IMAGE_TAG="${IMAGE_TAG}" \
        DOCKER_BUILDKIT=1 \
        -j"${NPROC}"

    echo "==> Building operator image..."
    make docker-operator-generic-image \
        DOCKER_IMAGE_TAG="${IMAGE_TAG}" \
        DOCKER_BUILDKIT=1 \
        -j"${NPROC}"
else
    echo "==> Skipping build (--no-build specified)"
fi

# ── 2. Export archives ────────────────────────────────────────────────────────
echo "==> Saving images to archives..."
docker save "${CILIUM_IMAGE}"   | gzip > "${CILIUM_ARCHIVE}"
docker save "${OPERATOR_IMAGE}" | gzip > "${OPERATOR_ARCHIVE}"

# ── 3. Distribute and import on each node ────────────────────────────────────
import_on_node() {
    local HOST="$1"
    local LABEL="$2"
    echo "==> [${LABEL}] Copying archives..."
    scp "${CILIUM_ARCHIVE}"   "${SSH_USER}@${HOST}:/tmp/"
    scp "${OPERATOR_ARCHIVE}" "${SSH_USER}@${HOST}:/tmp/"

    echo "==> [${LABEL}] Importing into k3s containerd (k8s.io namespace)..."
    # k3s bundles its own containerd — always use 'k3s ctr', not bare 'ctr'
    ssh "${SSH_USER}@${HOST}" \
        "gunzip -c /tmp/${CILIUM_ARCHIVE}   | sudo k3s ctr -n k8s.io images import -"
    ssh "${SSH_USER}@${HOST}" \
        "gunzip -c /tmp/${OPERATOR_ARCHIVE} | sudo k3s ctr -n k8s.io images import -"

    echo "==> [${LABEL}] Verifying..."
    ssh "${SSH_USER}@${HOST}" \
        "sudo k3s ctr -n k8s.io images list | grep '${IMAGE_TAG}'"

    echo "==> [${LABEL}] Cleaning up..."
    ssh "${SSH_USER}@${HOST}" \
        "rm /tmp/${CILIUM_ARCHIVE} /tmp/${OPERATOR_ARCHIVE}"

    echo "==> [${LABEL}] Done."
}

# Run imports in parallel on both nodes
import_on_node "${MASTER_IP}" "master" &
PID_MASTER=$!
import_on_node "${WORKER_IP}" "worker" &
PID_WORKER=$!

wait $PID_MASTER && echo "master import OK" || echo "master import FAILED"
wait $PID_WORKER && echo "worker import OK" || echo "worker import FAILED"

# ── 4. Clean up local archives ────────────────────────────────────────────────
rm "${CILIUM_ARCHIVE}" "${OPERATOR_ARCHIVE}"
echo "==> All done. Images are loaded on master and worker."
```

Run the full build + distribute cycle:
```bash
./build-push-save.sh
```

Or skip the build if images are already built locally:
```bash
./build-push-save.sh --no-build
```

Verify the images are visible on both nodes before proceeding:
```bash
# On each node
sudo k3s ctr -n k8s.io images list | grep vxlan-xdp-dev
# Expected output: two lines — one for cilium, one for operator-generic
```

---

#### Step 2 — Helm values file
>  The values file below is an **example** based on the cluster configuration used in this project. Adapt `k8sServiceHost`, IP ranges, interface names, and image tags to match your own environment before deploying.

Save the following as `cilium-values.yaml`. The `vxlanAcceleration` block is the key addition from Killian's patch; the rest mirrors the cluster's standard network configuration.

```yaml
# cilium-values.yaml — Modified Cilium with VXLAN XDP acceleration

k8sServiceHost: 10.4.100.1      # master's data-plane IP
k8sServicePort: 6443
kubeProxyReplacement: true

# ── Networking ────────────────────────────────────────────────────────────────
routingMode: tunnel
tunnelProtocol: vxlan
mtu: 1400                        # mandatory: pod MTU + 50-byte VXLAN header < 1500

ipam:
  mode: cluster-pool
  operator:
    clusterPoolIPv4PodCIDRList:
      - 10.42.0.0/16             # K3s default pod CIDR

bpf:
  masquerade: true
  legacyBPFLink: true            # required on older kernels to avoid BPF Link detach errors

enableIPv4Masquerade: true

# ── cgroup (required for K3s) ─────────────────────────────────────────────────
# K3s mounts its own cgroup hierarchy; disable auto-mount to avoid conflicts
cgroup:
  autoMount:
    enabled: false
  hostRoot: /sys/fs/cgroup

# ── VXLAN XDP acceleration (Killian's patch) ──────────────────────────────────
vxlanAcceleration:
  enabled: true
  enableMetrics: false
  queues: 1                      # set to 1 — Intel i40e requires single-queue for XDP Native
  enablePolicyEnforcement: true

# ── Custom image ──────────────────────────────────────────────────────────────
image:
  override: "quay.io/cilium/cilium:vxlan-xdp-dev"
  pullPolicy: "Never"            # images are pre-loaded via k3s ctr; no registry pull

operator:
  replicas: 1
  nodeSelector:
    kubernetes.io/hostname: master   # pin operator to master to avoid IPAM deadlock (Error E5)
  hostNetwork: true
  image:
    override: "quay.io/cilium/operator-generic:vxlan-xdp-dev"
    pullPolicy: "Never"

# ── Observability ─────────────────────────────────────────────────────────────
hubble:
  enabled: true
  metrics:
    enableOpenMetrics: true
  relay:
    enabled: true
  ui:
    enabled: true
    service:
      type: NodePort
      nodePort: 30080
    frontend:
      server:
        ipv6:
          enabled: false
  tls:
    auto:
      enabled: true
      method: helm
      certValidityDuration: 1095

prometheus:
  enabled: true
```

> **`queues: 1`:** The Intel X710 (`i40e`) driver only accepts XDP Native when the NIC is configured with a single hardware queue. Setting `queues: 1` in the `vxlanAcceleration` block tells the modified Cilium to enforce this at attach time. Attempting to use `queues > 1` will cause the driver to reject XDP and fall back silently (see Error E9 in [Standard Installation](#errors-and-solutions)).

---

#### Step 3 — Deploy

Apply the per-node device labels (same as the standard installation):
```bash
kubectl label nodes master hw-profile=master-layout
kubectl label nodes worker hw-profile=worker-layout
kubectl apply -f node-config.yaml   # the CiliumNodeConfig from standard install Step 3
```

Install or upgrade Cilium with the custom values:
```bash
helm upgrade --install cilium install/kubernetes/cilium \
  --namespace kube-system \
  --values cilium-values.yaml
```

> **Note on the chart path:** `install/kubernetes/cilium` is the path to the Helm chart within the modified Cilium source tree. If you prefer to use the upstream chart as base, use `cilium/cilium` from the `helm.cilium.io` repo and rely solely on the custom image override. The `vxlanAcceleration` values block will only take effect if the chart version includes Killian's modifications.

Monitor pod startup:
```bash
kubectl get pods -n kube-system -l k8s-app=cilium -w
```

---

#### Step 4 — Validation

```bash
# Confirm the custom image is running (not the upstream one)
kubectl get pods -n kube-system -l k8s-app=cilium \
  -o jsonpath='{range .items[*]}{.spec.containers[0].image}{"\n"}{end}'
# Expected: quay.io/cilium/cilium:vxlan-xdp-dev

# Check vxlanAcceleration is active in the agent
POD_MASTER=$(kubectl get pods -n kube-system -l k8s-app=cilium \
  --field-selector spec.nodeName=master -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n kube-system $POD_MASTER -c cilium-agent -- cilium status --verbose | grep -i xdp

# Verify XDP is attached to the physical NIC
ip link show eth0   # look for prog/xdp id <N>

# Verify VXLAN MTU
ip -d link show cilium_vxlan | grep mtu   # must show 1400
```

---

#### Known Issues

**ErrImageNeverPull on pod restart**
- **Cause:** A `kubectl delete pod` or node reboot triggers pod rescheduling before the `k3s ctr` import completes (or on a node where import was never done).
- **Fix:** Re-run `import_on_node` for the affected node, then delete the failing pod.
  ```bash
  sudo k3s ctr -n k8s.io images list | grep vxlan-xdp-dev
  # If missing, re-import:
  gunzip -c cilium-vxlan-xdp-dev.tar.gz | sudo k3s ctr -n k8s.io images import -
  kubectl delete pod -n kube-system <failing-pod>
  ```

**`k3s ctr` vs bare `ctr` — images not visible to the scheduler**
- **Cause:** K3s uses a private containerd socket at `/run/k3s/containerd/containerd.sock`. The system `ctr` binary (if installed) connects to `/run/containerd/containerd.sock` — a completely separate runtime. Images imported there are invisible to K3s.
- **Fix:** Always use `k3s ctr` (or `ctr --address /run/k3s/containerd/containerd.sock -n k8s.io`) for any import/list/remove operation targeting K3s pods.

**`helm upgrade` silently keeps old image after `--no-build` re-deploy**
- **Cause:** If the local Docker tag `vxlan-xdp-dev` was rebuilt but the old archive is still on the nodes, the pods will continue running the old binary. `pullPolicy: Never` prevents any runtime refresh.
- **Fix:** Always re-run the full build-push-save pipeline when the Cilium source changes. Verify the image digest after import:
  ```bash
  sudo k3s ctr -n k8s.io images list | grep vxlan-xdp-dev
  # Check the DIGEST column changes between builds
  ```

**operator image not overridden — operator pulls upstream**
- **Cause:** Forgetting to set `operator.image.override` in the values file causes the operator pod to use the upstream `cilium/operator-generic:v1.x.x` image, which does not include Killian's patches and may be incompatible with the modified agent.
- **Fix:** Ensure both `image.override` and `operator.image.override` are set in `cilium-values.yaml`.

