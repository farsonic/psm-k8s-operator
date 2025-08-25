#!/bin/bash

# This script applies all the necessary Kubernetes manifests to deploy the 3-tier application.
# It's recommended to run this from the directory containing all the YAML files.

echo "Applying NetworkAttachmentDefinitions for MACVLAN..."
kubectl apply -f macvlan-network-definitions.yaml

# Add a small delay to ensure the Custom Resource Definitions (CRDs) for networking are recognized
sleep 2

echo "Applying PSM Workload Registration Profiles..."
kubectl apply -f registration-web-tier.yaml
kubectl apply -f registration-app-tier.yaml
kubectl apply -f registration-db-tier.yaml

# Add a small delay to ensure the registration profiles are active
sleep 2

echo "Deploying the 3-tier application pods..."
kubectl apply -f 3-Tier-App.yaml

echo ""
echo "Deployment complete. Run 'kubectl get pods -o wide' to see the status."
echo ""
echo "The following security policy will be enforced by the PSM:"
echo ""

cat <<EOF
+-----------------------+--------------------------+--------------------+--------+----------------------------------------------------+
|  Source Tier (Label)  | Destination Tier (Label) |   Allowed Ports    | Action |                    Description                     |
+-----------------------+--------------------------+--------------------+--------+----------------------------------------------------+
|  Anywhere             |  tier: web               |  TCP/80, TCP/443   |  ALLOW |  Allows external users to access the web servers.  |
|  tier: web            |  tier: app               |  TCP/8080 (example)|  ALLOW |  Allows the web tier to communicate with the app.  |
|  tier: app            |  tier: db                |  TCP/5432 (example)|  ALLOW |  Allows the app tier to query the database.        |
|  Any                  |  Any                     |  All               |  DENY  |  Default Rule: All other traffic is denied.        |
+-----------------------+--------------------------+--------------------+--------+----------------------------------------------------+
EOF


