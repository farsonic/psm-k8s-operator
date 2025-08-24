#!/bin/bash

# PSM Operator Quick Configuration Script

echo "PSM Operator Quick Setup"
echo "========================"

# Get PSM server details
read -p "Enter PSM Server IP [192.168.0.58]: " PSM_IP
PSM_IP=${PSM_IP:-192.168.0.58}

read -p "Enter PSM Username [admin]: " PSM_USER
PSM_USER=${PSM_USER:-admin}

read -s -p "Enter PSM Password: " PSM_PASS
echo

# Download the install manifest
echo "Downloading install manifest..."
curl -sL https://raw.githubusercontent.com/farsonic/psm-k8s-operator/main/deploy/install.yaml -o psm-operator-install.yaml

# Replace placeholders
echo "Configuring manifest..."
sed -i "s/CHANGE_ME_PSM_IP/$PSM_IP/g" psm-operator-install.yaml
sed -i "s/CHANGE_ME_PSM_PASSWORD/$PSM_PASS/g" psm-operator-install.yaml
sed -i "s/username: admin/username: $PSM_USER/g" psm-operator-install.yaml

# Apply the manifest
echo "Installing PSM Operator..."
kubectl apply -f psm-operator-install.yaml

echo ""
echo "Installation complete! Check status with:"
echo "  kubectl get pods -n psm-operator-system"
echo "  kubectl get psmworkloadregistrations"
