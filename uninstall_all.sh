#!/bin/bash
set -e

# This script removes all components installed by the install_all.sh script.

echo "### Step 1: Uninstalling the PSM Operator Helm Release ###"
helm uninstall psm-operator -n psm-operator-system

echo ""
echo "### Step 2: Deleting RBAC Permissions ###"
kubectl delete clusterrolebinding psm-operator-secret-reader --ignore-not-found=true
kubectl delete clusterrole psm-operator-secret-reader --ignore-not-found=true

echo ""
echo "### Step 3: Deleting PSM Credentials Secret ###"
kubectl delete secret psm-credentials --namespace=default --ignore-not-found=true

echo ""
echo "### Step 4: Uninstalling Whereabouts ###"
if [ -d "whereabouts" ]; then
  cd whereabouts
  kubectl delete \
      -f doc/crds/daemonset-install.yaml \
      -f doc/crds/whereabouts.cni.cncf.io_ippools.yaml \
      -f doc/crds/whereabouts.cni.cncf.io_overlappingrangeipreservations.yaml \
      --ignore-not-found=true
  cd ..
else
  echo "Whereabouts directory not found, skipping CNI deletion. You may need to delete these resources manually."
fi

echo ""
echo "### Step 5: Uninstalling Multus ###"
kubectl delete -f https://raw.githubusercontent.com/k8snetworkplumbingwg/multus-cni/master/deployments/multus-daemonset-thick.yml --ignore-not-found=true

echo ""
echo "### Step 6: Uninstalling Flannel ###"
kubectl delete -f https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml --ignore-not-found=true

echo ""
echo "### Step 7: Resetting Kubernetes Nodes (MANUAL STEP) ###"
echo "To completely tear down the cluster, run 'sudo kubeadm reset' on all worker nodes and the control plane node."
echo "Example: sudo kubeadm reset -f"

echo ""
echo "Uninstallation script finished."

