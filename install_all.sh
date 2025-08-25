#!/bin/bash
set -e

# This script automates the setup of a Kubernetes cluster and the PSM Operator.
# It will prompt for necessary information like IP addresses and credentials.

echo "### Step 1: Initializing Kubernetes Control Plane ###"
read -p "Please enter the IP address of this control plane node: " CONTROL_PLANE_IP

if [ -z "$CONTROL_PLANE_IP" ]; then
  echo "Error: Control plane IP address cannot be empty."
  exit 1
fi

echo "Initializing Kubernetes with advertise address: $CONTROL_PLANE_IP"
sudo kubeadm init \
  --pod-network-cidr=10.244.0.0/16 \
  --apiserver-advertise-address=$CONTROL_PLANE_IP

echo "### Step 2: Setting up kubeconfig for the current user ###"
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
echo "Kubeconfig set up."

echo ""
echo "### Step 3: Installing Flannel CNI ###"
kubectl apply -f https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml
echo "Flannel installation command issued."

echo ""
echo "### Step 4: Joining Worker Nodes (MANUAL STEP) ###"
echo "Please run the 'kubeadm join' command (output from the 'kubeadm init' step) on each of your worker nodes."
echo "Example: sudo kubeadm join 192.168.1.10:6443 --token <TOKEN> --discovery-token-ca-cert-hash sha256:<HASH>"
read -p "Press Enter once all worker nodes have joined the cluster..."

echo ""
echo "### Step 4.5: Configure Worker Node Interfaces (MANUAL STEP) ###"
echo "On EACH worker node, you must now create the VLAN sub-interfaces for MACVLAN."
echo "Run the following commands on each worker:"
echo ""
cat << EOF
# --- Run these commands on each worker node (assumes 'ens19' is the physical interface) ---
sudo ip link add link ens19 name vlan.20 type vlan id 20
sudo ip link add link ens19 name vlan.21 type vlan id 21
sudo ip link add link ens19 name vlan.22 type vlan id 22

sudo ip link set up vlan.20
sudo ip link set up vlan.21
sudo ip link set up vlan.22
# ------------------------------------------------------------------------------------
EOF
echo ""
read -p "Press Enter once you have configured the interfaces on all worker nodes..."


echo ""
echo "### Step 5: Installing Multus CNI ###"
kubectl apply -f https://raw.githubusercontent.com/k8snetworkplumbingwg/multus-cni/master/deployments/multus-daemonset-thick.yml
echo "Multus installation command issued."

echo ""
echo "### Step 6: Installing Whereabouts IPAM ###"
if [ ! -d "whereabouts" ]; then
  git clone https://github.com/k8snetworkplumbingwg/whereabouts
fi
cd whereabouts
kubectl apply \
    -f doc/crds/daemonset-install.yaml \
    -f doc/crds/whereabouts.cni.cncf.io_ippools.yaml \
    -f doc/crds/whereabouts.cni.cncf.io_overlappingrangeipreservations.yaml
cd ..
echo "Whereabouts installation command issued."

echo ""
echo "### Step 7: Setting up Helm ###"
if ! command -v helm &> /dev/null
then
    echo "Helm not found. Installing..."
    curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
    chmod 700 get_helm.sh
    ./get_helm.sh
fi
echo "Adding PSM operator Helm repository..."
helm repo add psm-operator https://farsonic.github.io/psm-k8s-operator
helm repo update
echo "Helm is ready."

echo ""
echo "### Step 8: Creating PSM Credentials Secret ###"
read -p "Please enter your PSM username: " PSM_USERNAME
read -s -p "Please enter your PSM password: " PSM_PASSWORD
echo ""

if [ -z "$PSM_USERNAME" ] || [ -z "$PSM_PASSWORD" ]; then
  echo "Error: PSM username and password cannot be empty."
  exit 1
fi

kubectl create secret generic psm-credentials \
  --from-literal=username="$PSM_USERNAME" \
  --from-literal=password="$PSM_PASSWORD" \
  --namespace=default

echo ""
echo "### Step 9: Installing the PSM Operator ###"
read -p "Please enter the IP address of your PSM server: " PSM_SERVER_IP

if [ -z "$PSM_SERVER_IP" ]; then
  echo "Error: PSM server IP address cannot be empty."
  exit 1
fi

helm install psm-operator psm-operator/psm-operator \
  --namespace psm-operator-system \
  --create-namespace \
  --version 0.2.0 \
  --set psmServer.host="$PSM_SERVER_IP"

echo ""
echo "### Step 10: Fixing RBAC Permissions ###"
kubectl create clusterrole psm-operator-secret-reader --verb=get,list,watch --resource=secrets
kubectl create clusterrolebinding psm-operator-secret-reader \
  --clusterrole=psm-operator-secret-reader \
  --serviceaccount=psm-operator-system:psm-operator

echo ""
echo "### Step 11: Verifying Installation ###"
echo "Checking Helm release status..."
helm list -n psm-operator-system
echo ""
echo "Checking operator pods (they might take a minute to become Ready)..."
kubectl get pods -n psm-operator-system

echo ""
echo "Installation script finished."

