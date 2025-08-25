#!/bin/bash

# This script deletes all the Kubernetes manifests associated with the 3-tier application.
# It includes a wait command to ensure pods are terminated before their registration profiles are removed.

echo "Deleting the 3-tier application pods..."
kubectl delete -f 3-Tier-App.yaml

echo "Waiting for all pods to be completely terminated..."
# This command waits until it can no longer find any pods with the label 'psm=True'
# The timeout is set to 2 minutes.
#kubectl wait --for=delete pod -l psm=True --timeout=120s

echo "All pods have been terminated."
echo ""

echo "Deleting the PSM Workload Registration Profiles..."
kubectl delete -f registration-web-tier.yaml
kubectl delete -f registration-app-tier.yaml
kubectl delete -f registration-db-tier.yaml

echo "Deleting the NetworkAttachmentDefinitions..."
kubectl delete -f macvlan-network-definitions.yaml

echo ""
echo "Teardown complete."


