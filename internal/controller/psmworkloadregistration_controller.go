/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"text/template"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	psmoperatorv1alpha1 "psm.microseglab.com/psm-operator/api/v1alpha1"
)

// PsmWorkloadRegistrationReconciler reconciles a PsmWorkloadRegistration object
type PsmWorkloadRegistrationReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// PSM Network API structures
type PsmNetworkRequest struct {
	Kind       interface{}          `json:"kind"`
	APIVersion interface{}          `json:"api-version"`
	Meta       PsmNetworkMeta       `json:"meta"`
	Spec       PsmNetworkSpec       `json:"spec"`
}

type PsmNetworkMeta struct {
	Name      string      `json:"name"`
	Tenant    string      `json:"tenant"`
	Namespace interface{} `json:"namespace"`
	Labels    interface{} `json:"labels"`
}

type PsmNetworkSpec struct {
	VlanID         int         `json:"vlan-id"`
	VirtualRouter  string      `json:"virtual-router"`
	Subnet         string      `json:"subnet,omitempty"`
	Gateway        string      `json:"gateway,omitempty"`
	VNI            interface{} `json:"vni"`
}

type PsmVirtualRouterRequest struct {
	Kind       interface{}              `json:"kind"`
	APIVersion interface{}              `json:"api-version"`
	Meta       PsmVirtualRouterMeta     `json:"meta"`
	Spec       PsmVirtualRouterSpec     `json:"spec"`
}

type PsmVirtualRouterMeta struct {
	Name      string      `json:"name"`
	Tenant    string      `json:"tenant"`
	Namespace interface{} `json:"namespace"`
	Labels    interface{} `json:"labels"`
}

type PsmVirtualRouterSpec struct {
	Type string `json:"type"`
}

//+kubebuilder:rbac:groups=psm-operator.psm.microseglab.com,resources=psmworkloadregistrations,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=psm-operator.psm.microseglab.com,resources=psmworkloadregistrations/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=psm-operator.psm.microseglab.com,resources=psmworkloadregistrations/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=pods/exec,verbs=create
//+kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// Enhanced convertMACFormat with better validation
func (r *PsmWorkloadRegistrationReconciler) convertMACFormat(macAddr string) string {
	if macAddr == "" {
		return ""
	}

	// Handle different input formats
	var cleanMAC string
	
	if strings.Contains(macAddr, ":") {
		// Standard format: aa:bb:cc:dd:ee:ff
		cleanMAC = strings.ReplaceAll(macAddr, ":", "")
	} else if strings.Contains(macAddr, "-") {
		// Windows format: aa-bb-cc-dd-ee-ff
		cleanMAC = strings.ReplaceAll(macAddr, "-", "")
	} else {
		// Already clean or unknown format
		cleanMAC = macAddr
	}

	// Convert to lowercase
	cleanMAC = strings.ToLower(cleanMAC)

	// Validate length
	if len(cleanMAC) != 12 {
		// Invalid MAC address length
		return "0000.0000.0000"
	}

	// Convert to PSM dot format: aabbccddeeff -> aabb.ccdd.eeff
	return fmt.Sprintf("%s.%s.%s",
		cleanMAC[0:4],
		cleanMAC[4:8],
		cleanMAC[8:12])
}

// ensurePsmNetworkExists ensures that a network exists in PSM for the given MACVLAN interface
func (r *PsmWorkloadRegistrationReconciler) ensurePsmNetworkExists(
	ctx context.Context,
	httpClient *http.Client,
	reg *psmoperatorv1alpha1.PsmWorkloadRegistration,
	macvlanSpec psmoperatorv1alpha1.MacvlanInterfaceSpec,
	username, password string,
) error {
	logger := log.FromContext(ctx)
	
	// Skip if PSM network redirection is not enabled
	if !macvlanSpec.PsmNetworkRedirection {
		return nil
	}

	// Validate required fields for network creation
	if macvlanSpec.VlanID == nil {
		return fmt.Errorf("vlanId is required when psmNetworkRedirection is enabled")
	}
	if macvlanSpec.PsmVirtualRouter == "" {
		return fmt.Errorf("psmVirtualRouter is required when psmNetworkRedirection is enabled")
	}
	if macvlanSpec.PsmNetworkName == "" {
		return fmt.Errorf("psmNetworkName is required when psmNetworkRedirection is enabled")
	}

	tenant := reg.Spec.PsmServer.Tenant
	if tenant == "" {
		tenant = "default"
	}

	// First ensure the virtual router exists
	if err := r.ensurePsmVirtualRouterExists(ctx, httpClient, reg, macvlanSpec.PsmVirtualRouter, username, password); err != nil {
		return fmt.Errorf("failed to ensure virtual router exists: %w", err)
	}

	// Check if network already exists
	networkExists, err := r.checkPsmNetworkExists(ctx, httpClient, reg, *macvlanSpec.VlanID, username, password)
	if err != nil {
		return fmt.Errorf("failed to check network existence: %w", err)
	}

	if networkExists {
		logger.Info("PSM network already exists", "vlanId", *macvlanSpec.VlanID, "networkName", macvlanSpec.PsmNetworkName)
		return nil
	}

	// Create the network
	logger.Info("Creating PSM network", "vlanId", *macvlanSpec.VlanID, "networkName", macvlanSpec.PsmNetworkName, "virtualRouter", macvlanSpec.PsmVirtualRouter)

	networkPayload := PsmNetworkRequest{
		Kind:       nil,
		APIVersion: nil,
		Meta: PsmNetworkMeta{
			Name:      macvlanSpec.PsmNetworkName,
			Tenant:    tenant,
			Namespace: nil,
			Labels:    nil,
		},
		Spec: PsmNetworkSpec{
			VlanID:        *macvlanSpec.VlanID,
			VirtualRouter: macvlanSpec.PsmVirtualRouter,
			Subnet:        macvlanSpec.NetworkSubnet,
			Gateway:       macvlanSpec.GatewayIP,
			VNI:           nil,
		},
	}

	payloadBytes, err := json.Marshal(networkPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal network payload: %w", err)
	}

	createURL := fmt.Sprintf("https://%s/configs/network/v1/networks", reg.Spec.PsmServer.Host)
	req, err := http.NewRequestWithContext(ctx, "POST", createURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create network creation request: %w", err)
	}

	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("Authorization", "Basic "+auth)

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create network: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create network in PSM, status: %d, body: %s", resp.StatusCode, string(body))
	}

	logger.Info("Successfully created PSM network", "networkName", macvlanSpec.PsmNetworkName, "vlanId", *macvlanSpec.VlanID)
	return nil
}

// ensurePsmVirtualRouterExists ensures that a virtual router (VRF) exists in PSM
func (r *PsmWorkloadRegistrationReconciler) ensurePsmVirtualRouterExists(
	ctx context.Context,
	httpClient *http.Client,
	reg *psmoperatorv1alpha1.PsmWorkloadRegistration,
	vrfName string,
	username, password string,
) error {
	logger := log.FromContext(ctx)
	
	tenant := reg.Spec.PsmServer.Tenant
	if tenant == "" {
		tenant = "default"
	}

	// Check if virtual router already exists
	checkURL := fmt.Sprintf("https://%s/configs/network/v1/tenant/%s/virtualrouters/%s", reg.Spec.PsmServer.Host, tenant, vrfName)
	req, err := http.NewRequestWithContext(ctx, "GET", checkURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create VRF check request: %w", err)
	}

	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	req.Header.Add("Authorization", "Basic "+auth)

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to check VRF existence: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		logger.Info("PSM virtual router already exists", "vrf", vrfName)
		return nil
	}

	// Virtual router doesn't exist, create it
	logger.Info("Creating PSM virtual router", "vrf", vrfName)

	vrfPayload := PsmVirtualRouterRequest{
		Kind:       nil,
		APIVersion: nil,
		Meta: PsmVirtualRouterMeta{
			Name:      vrfName,
			Tenant:    tenant,
			Namespace: nil,
			Labels:    nil,
		},
		Spec: PsmVirtualRouterSpec{
			Type: "infra", // or "tenant" based on your requirements
		},
	}

	payloadBytes, err := json.Marshal(vrfPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal VRF payload: %w", err)
	}

	createURL := fmt.Sprintf("https://%s/configs/network/v1/tenant/%s/virtualrouters", reg.Spec.PsmServer.Host, tenant)
	req, err = http.NewRequestWithContext(ctx, "POST", createURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create VRF creation request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("Authorization", "Basic "+auth)

	resp, err = httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create VRF: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create VRF in PSM, status: %d, body: %s", resp.StatusCode, string(body))
	}

	logger.Info("Successfully created PSM virtual router", "vrf", vrfName)
	return nil
}

// checkPsmNetworkExists checks if a network with the given VLAN ID exists in PSM
func (r *PsmWorkloadRegistrationReconciler) checkPsmNetworkExists(
	ctx context.Context,
	httpClient *http.Client,
	reg *psmoperatorv1alpha1.PsmWorkloadRegistration,
	vlanID int,
	username, password string,
) (bool, error) {
	logger := log.FromContext(ctx)

	networksURL := fmt.Sprintf("https://%s/configs/network/v1/networks", reg.Spec.PsmServer.Host)
	req, err := http.NewRequestWithContext(ctx, "GET", networksURL, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create networks list request: %w", err)
	}

	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	req.Header.Add("Authorization", "Basic "+auth)

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to list networks: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("failed to list networks from PSM, status: %d, body: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read networks response: %w", err)
	}

	// Parse the networks list response
	var networksList struct {
		Items []struct {
			Spec struct {
				VlanID int `json:"vlan-id"`
			} `json:"spec"`
		} `json:"items"`
	}

	if err := json.Unmarshal(body, &networksList); err != nil {
		logger.Error(err, "Failed to parse networks list response")
		return false, nil
	}

	// Check if any network has the matching VLAN ID
	for _, network := range networksList.Items {
		if network.Spec.VlanID == vlanID {
			return true, nil
		}
	}

	return false, nil
}

// ensureHostExistsInPsm creates a host in PSM if it doesn't exist
func (r *PsmWorkloadRegistrationReconciler) ensureHostExistsInPsm(
	ctx context.Context,
	client *http.Client,
	reg *psmoperatorv1alpha1.PsmWorkloadRegistration,
	nodeName string,
	username, password string,
) error {
	logger := log.FromContext(ctx)
	tenant := reg.Spec.PsmServer.Tenant
	if tenant == "" {
		tenant = "default"
	}

	// First, check if host already exists
	checkURL := fmt.Sprintf("https://%s/configs/cluster/v1/hosts/%s", reg.Spec.PsmServer.Host, nodeName)
	req, err := http.NewRequestWithContext(ctx, "GET", checkURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create host check request: %w", err)
	}

	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	req.Header.Add("Authorization", "Basic "+auth)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to check host existence: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		logger.Info("Host already exists in PSM", "host", nodeName)
		return nil
	}

	// Host doesn't exist, create it
	logger.Info("Creating host in PSM", "host", nodeName)

	// Get the node object to extract MAC address
	node := &corev1.Node{}
	if err := r.Get(ctx, types.NamespacedName{Name: nodeName}, node); err != nil {
		return fmt.Errorf("failed to get node %s: %w", nodeName, err)
	}

	// Extract the node's primary interface MAC address
	primaryMAC, err := r.getNodePrimaryMAC(ctx, node)
	if err != nil {
		logger.Error(err, "Failed to get primary MAC for node, using default", "node", nodeName)
		primaryMAC = "0000.0000.0000" // Fallback MAC
	}

	// Create host payload
	hostPayload := map[string]interface{}{
		"kind":        nil,
		"api-version": nil,
		"meta": map[string]interface{}{
			"name":           nodeName,
			"tenant":         nil,
			"namespace":      nil,
			"generation-id":  nil,
			"resource-version": nil,
			"uuid":           nil,
			"labels":         nil,
			"self-link":      nil,
			"display-name":   nil,
		},
		"spec": map[string]interface{}{
			"pnic-info": []map[string]string{
				{
					"mac-address": primaryMAC,
					"name":        "eth0",
				},
			},
			"hostType": "pnic",
		},
	}

	payloadBytes, err := json.Marshal(hostPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal host payload: %w", err)
	}

	createURL := fmt.Sprintf("https://%s/configs/cluster/v1/hosts", reg.Spec.PsmServer.Host)
	req, err = http.NewRequestWithContext(ctx, "POST", createURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create host creation request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("Authorization", "Basic "+auth)

	resp, err = client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create host: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create host in PSM, status: %d, body: %s", resp.StatusCode, string(body))
	}

	logger.Info("Successfully created host in PSM", "host", nodeName)
	return nil
}

// getNodePrimaryMAC extracts the primary interface MAC address from a node
func (r *PsmWorkloadRegistrationReconciler) getNodePrimaryMAC(ctx context.Context, node *corev1.Node) (string, error) {
	// Try to get MAC from node annotations first
	if macAddr, exists := node.Annotations["node.alpha.kubernetes.io/primary-mac"]; exists {
		return r.convertMACFormat(macAddr), nil
	}

	// Try to extract from node addresses or other metadata
	// This is a simplified approach - you might need to adjust based on your cluster setup
	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeInternalIP {
			// In a real implementation, you might need to query the node directly
			// For now, we'll generate a placeholder based on the IP
			return "0000.0000.0000", fmt.Errorf("could not determine primary MAC for node %s", node.Name)
		}
	}

	return "0000.0000.0000", fmt.Errorf("could not find primary interface for node %s", node.Name)
}

// Enhanced status update method with retry logic
func (r *PsmWorkloadRegistrationReconciler) updateStatusWithRetry(
	ctx context.Context, 
	reg *psmoperatorv1alpha1.PsmWorkloadRegistration,
	synchronizedPods []string,
	activeWorkloads int,
) error {
	logger := log.FromContext(ctx)
	
	// Use exponential backoff for retries
	maxRetries := 3
	baseDelay := time.Millisecond * 100
	
	for attempt := 0; attempt < maxRetries; attempt++ {
		// Get the latest version of the resource
		latest := &psmoperatorv1alpha1.PsmWorkloadRegistration{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(reg), latest); err != nil {
			logger.Error(err, "Failed to get latest resource version for status update")
			return err
		}
		
		// Update the status on the latest version
		now := metav1.NewTime(time.Now())
		latest.Status.SynchronizedPods = synchronizedPods
		latest.Status.LastSyncTime = &now
		latest.Status.ActiveWorkloads = activeWorkloads
		
		// Attempt to update status
		if err := r.Status().Update(ctx, latest); err != nil {
			if errors.IsConflict(err) && attempt < maxRetries-1 {
				// Resource version conflict, wait and retry
				delay := time.Duration(1<<attempt) * baseDelay // Exponential backoff
				logger.V(1).Info("Status update conflict, retrying", 
					"attempt", attempt+1, 
					"delay", delay.String())
				time.Sleep(delay)
				continue
			}
			logger.Error(err, "Failed to update status after retries", "attempts", attempt+1)
			return err
		}
		
		// Success
		logger.V(1).Info("Successfully updated status", "attempt", attempt+1)
		return nil
	}
	
	return fmt.Errorf("failed to update status after %d attempts", maxRetries)
}

func (r *PsmWorkloadRegistrationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Reconciliation started")

	// 1. Fetch the PsmWorkloadRegistration instance
	reg := &psmoperatorv1alpha1.PsmWorkloadRegistration{}
	if err := r.Get(ctx, req.NamespacedName, reg); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("PsmWorkloadRegistration resource not found. Ignoring.")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get PsmWorkloadRegistration")
		return ctrl.Result{}, err
	}

	// 2. Fetch PSM credentials from the specified Secret
	secret := &corev1.Secret{}
	secretName := types.NamespacedName{
		Namespace: req.Namespace,
		Name:      reg.Spec.PsmServer.CredentialsSecretRef.Name,
	}
	if err := r.Get(ctx, secretName, secret); err != nil {
		if errors.IsNotFound(err) {
			logger.Error(err, "Credentials secret not found")
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
		logger.Error(err, "Failed to get credentials secret")
		return ctrl.Result{}, err
	}

	// Decode username and password
	usernameBytes, ok := secret.Data["username"]
	if !ok {
		err := fmt.Errorf("username key not found in secret %s", secret.Name)
		logger.Error(err, "Secret validation failed")
		return ctrl.Result{}, nil
	}
	passwordBytes, ok := secret.Data["password"]
	if !ok {
		err := fmt.Errorf("password key not found in secret %s", secret.Name)
		logger.Error(err, "Secret validation failed")
		return ctrl.Result{}, nil
	}

	decodedUsername := string(usernameBytes)
	decodedPassword := string(passwordBytes)

	// Create HTTP client with cookie jar for session management
	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	httpClient := &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second, // Increased timeout for exec operations
		Jar:       jar,
	}

	// Login to PSM first
	if err := r.loginToPsm(ctx, httpClient, reg, decodedUsername, decodedPassword); err != nil {
		logger.Error(err, "Failed to login to PSM")
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// 3. List all pods matching the selector
	podList := &corev1.PodList{}
	labelSelector, err := metav1.LabelSelectorAsSelector(&reg.Spec.PodSelector)
	if err != nil {
		logger.Error(err, "Failed to create label selector from spec")
		return ctrl.Result{}, nil
	}
	listOpts := &client.ListOptions{
		Namespace:     req.Namespace,
		LabelSelector: labelSelector,
	}
	if err := r.List(ctx, podList, listOpts); err != nil {
		logger.Error(err, "Failed to list pods")
		return ctrl.Result{}, err
	}

	// 4. Process pods based on their lifecycle state
	synchronizedPods := make(map[string]bool)
	if reg.Status.SynchronizedPods != nil {
		for _, podName := range reg.Status.SynchronizedPods {
			synchronizedPods[podName] = true
		}
	}

	// Enhanced synchronization: verify actual PSM state
	actualPsmWorkloads, err := r.listWorkloadsInPsm(ctx, httpClient, reg, decodedUsername, decodedPassword)
	if err != nil {
		logger.Error(err, "Failed to list workloads from PSM, continuing with cached state")
		// Continue with cached state rather than failing
	} else {
		logger.V(1).Info("Found workloads in PSM", "count", len(actualPsmWorkloads), "workloads", actualPsmWorkloads)
	}

	// Process each pod individually based on its state
	for _, pod := range podList.Items {
		podCopy := pod // Create copy to avoid loop variable issues
		
		// Handle pod lifecycle changes
		switch pod.Status.Phase {
		case corev1.PodRunning:
			if pod.Status.PodIP != "" {
				// Pod is running with IP - ensure it's registered/updated
				if err := r.handleRunningPod(ctx, httpClient, reg, &podCopy, decodedUsername, decodedPassword, synchronizedPods); err != nil {
					logger.Error(err, "Failed to handle running pod", "Pod", pod.Name)
					// Continue processing other pods
				}
			}
		case corev1.PodPending:
			// Pod is pending - remove from PSM if it was previously registered
			if _, wasSynced := synchronizedPods[pod.Name]; wasSynced {
				logger.Info("Pod moved to Pending state, removing from PSM", "Pod", pod.Name)
				if err := r.deregisterPodFromPsm(ctx, httpClient, reg, &podCopy, decodedUsername, decodedPassword); err != nil {
					logger.Error(err, "Failed to deregister pending pod", "Pod", pod.Name)
				} else {
					delete(synchronizedPods, pod.Name)
				}
			}
		case corev1.PodSucceeded, corev1.PodFailed:
			// Pod completed or failed - remove from PSM
			if _, wasSynced := synchronizedPods[pod.Name]; wasSynced {
				logger.Info("Pod completed/failed, removing from PSM", "Pod", pod.Name, "Phase", pod.Status.Phase)
				if err := r.deregisterPodFromPsm(ctx, httpClient, reg, &podCopy, decodedUsername, decodedPassword); err != nil {
					logger.Error(err, "Failed to deregister completed pod", "Pod", pod.Name)
				} else {
					delete(synchronizedPods, pod.Name)
				}
			}
		}
	}

	// Handle deleted pods - pods that were synchronized but no longer exist
	currentPodNames := make(map[string]bool)
	for _, pod := range podList.Items {
		currentPodNames[pod.Name] = true
	}

	for syncedPodName := range synchronizedPods {
		if !currentPodNames[syncedPodName] {
			logger.Info("Pod was deleted, removing from PSM", "Pod", syncedPodName)
			dummyPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: syncedPodName}}
			if err := r.deregisterPodFromPsm(ctx, httpClient, reg, dummyPod, decodedUsername, decodedPassword); err != nil {
				logger.Error(err, "Failed to deregister deleted pod", "Pod", syncedPodName)
				// Continue anyway
			}
			delete(synchronizedPods, syncedPodName)
		}
	}

	// 5. Update the status with retry logic
	updatedSyncList := make([]string, 0, len(synchronizedPods))
	for podName := range synchronizedPods {
		updatedSyncList = append(updatedSyncList, podName)
	}

	// Use the retry method for status updates
	if err := r.updateStatusWithRetry(ctx, reg, updatedSyncList, len(synchronizedPods)); err != nil {
		logger.Error(err, "Failed to update status with retry")
		// Don't fail the reconciliation for status update errors
		// The status will eventually be consistent
		logger.Info("Continuing reconciliation despite status update failure")
	}

	logger.Info("Reconciliation finished successfully")
	return ctrl.Result{}, nil
}

// handleRunningPod processes a running pod - registers or updates it in PSM
func (r *PsmWorkloadRegistrationReconciler) handleRunningPod(
	ctx context.Context,
	httpClient *http.Client,
	reg *psmoperatorv1alpha1.PsmWorkloadRegistration,
	pod *corev1.Pod,
	username, password string,
	synchronizedPods map[string]bool,
) error {
	logger := log.FromContext(ctx)
	
	// Check if pod has MACVLAN interfaces
	interfaces, err := r.extractNetworkInterfaces(ctx, pod, reg)
	if err != nil {
		logger.Error(err, "Failed to extract network interfaces", "Pod", pod.Name)
		return err
	}

	// Only process pods that have MACVLAN interfaces (if configured)
	if len(reg.Spec.NetworkContext.MacvlanInterfaces) > 0 && len(interfaces) == 0 {
		logger.V(1).Info("Pod has no MACVLAN interfaces, skipping", "Pod", pod.Name)
		return nil
	}

	// Ensure PSM networks exist for each MACVLAN interface (if redirection enabled)
	for _, macvlanSpec := range reg.Spec.NetworkContext.MacvlanInterfaces {
		if err := r.ensurePsmNetworkExists(ctx, httpClient, reg, macvlanSpec, username, password); err != nil {
			logger.Error(err, "Failed to ensure PSM network exists", "networkName", macvlanSpec.PsmNetworkName)
			// Continue anyway - the workload registration might still work
		}
	}

	// Ensure the host exists in PSM before registering the workload
	if err := r.ensureHostExistsInPsm(ctx, httpClient, reg, pod.Spec.NodeName, username, password); err != nil {
		logger.Error(err, "Failed to ensure host exists in PSM", "Node", pod.Spec.NodeName)
		// Continue anyway - the workload registration might still work
	}

	// Check if we need to register or update
	_, wasSynced := synchronizedPods[pod.Name]
	
	if !wasSynced {
		// New pod - register it
		logger.Info("New pod with MACVLAN interfaces detected, registering with PSM", "Pod", pod.Name, "Interfaces", len(interfaces))
		if err := r.registerPodWithPsm(ctx, httpClient, reg, pod, username, password); err != nil {
			return fmt.Errorf("failed to register pod: %w", err)
		}
		synchronizedPods[pod.Name] = true
	} else {
		// Existing pod - check if we need to update (labels or interfaces changed)
		logger.Info("Updating existing pod in PSM", "Pod", pod.Name, "Interfaces", len(interfaces))
		if err := r.updatePodInPsm(ctx, httpClient, reg, pod, username, password); err != nil {
			logger.Error(err, "Failed to update pod in PSM", "Pod", pod.Name)
			// Don't remove from synchronized set on update failure
			return err
		}
	}

	return nil
}

// registerPodWithPsm registers a new pod with PSM
func (r *PsmWorkloadRegistrationReconciler) registerPodWithPsm(
	ctx context.Context,
	httpClient *http.Client,
	reg *psmoperatorv1alpha1.PsmWorkloadRegistration,
	pod *corev1.Pod,
	username, password string,
) error {
	return r.syncWorkloadToPsm(ctx, httpClient, reg, pod, username, password, "POST")
}

// updatePodInPsm updates an existing pod in PSM
func (r *PsmWorkloadRegistrationReconciler) updatePodInPsm(
	ctx context.Context,
	httpClient *http.Client,
	reg *psmoperatorv1alpha1.PsmWorkloadRegistration,
	pod *corev1.Pod,
	username, password string,
) error {
	return r.syncWorkloadToPsm(ctx, httpClient, reg, pod, username, password, "PUT")
}

// deregisterPodFromPsm removes a pod from PSM
func (r *PsmWorkloadRegistrationReconciler) deregisterPodFromPsm(
	ctx context.Context,
	httpClient *http.Client,
	reg *psmoperatorv1alpha1.PsmWorkloadRegistration,
	pod *corev1.Pod,
	username, password string,
) error {
	return r.syncWorkloadToPsm(ctx, httpClient, reg, pod, username, password, "DELETE")
}

// Enhanced extractNetworkInterfaces with improved MACVLAN support
func (r *PsmWorkloadRegistrationReconciler) extractNetworkInterfaces(
	ctx context.Context,
	pod *corev1.Pod,
	reg *psmoperatorv1alpha1.PsmWorkloadRegistration,
) ([]psmoperatorv1alpha1.NetworkInterface, error) {
	logger := log.FromContext(ctx)
	var interfaces []psmoperatorv1alpha1.NetworkInterface

	// Include primary interface if requested
	if reg.Spec.NetworkContext.IncludePrimaryInterface {
		// Extract primary interface MAC via exec if possible
		primaryMAC, err := r.extractPrimaryInterfaceMAC(ctx, pod)
		if err != nil {
			logger.Error(err, "Failed to extract primary interface MAC", "Pod", pod.Name)
			primaryMAC = "" // Continue without MAC
		}

		interfaces = append(interfaces, psmoperatorv1alpha1.NetworkInterface{
			Name:        "eth0",
			IPAddress:   pod.Status.PodIP,
			MACAddress:  primaryMAC,
			NetworkName: reg.Spec.NetworkContext.PodNetworkName,
			Type:        "primary",
		})
	}

	// Extract MACVLAN interfaces with enhanced detection
	for _, macvlanSpec := range reg.Spec.NetworkContext.MacvlanInterfaces {
		interfaceInfo, err := r.extractMacvlanInterfaceEnhanced(ctx, pod, macvlanSpec)
		if err != nil {
			logger.Error(err, "Failed to extract MACVLAN interface",
				"Pod", pod.Name,
				"Interface", macvlanSpec.NetworkAttachmentName)
			continue // Skip this interface but continue with others
		}
		
		if interfaceInfo.IPAddress != "" {
			interfaces = append(interfaces, interfaceInfo)
			logger.Info("Successfully extracted MACVLAN interface",
				"Pod", pod.Name,
				"Interface", interfaceInfo.Name,
				"IP", interfaceInfo.IPAddress,
				"MAC", interfaceInfo.MACAddress)
		}
	}

	logger.Info("Extracted network interfaces", "Pod", pod.Name, "Count", len(interfaces))
	return interfaces, nil
}

// Enhanced extractMacvlanInterfaceEnhanced provides enhanced MACVLAN interface extraction
func (r *PsmWorkloadRegistrationReconciler) extractMacvlanInterfaceEnhanced(
	ctx context.Context,
	pod *corev1.Pod,
	macvlanSpec psmoperatorv1alpha1.MacvlanInterfaceSpec,
) (psmoperatorv1alpha1.NetworkInterface, error) {
	logger := log.FromContext(ctx)
	
	// Look for network status annotation from Multus/CNI
	networkStatusAnnotation := "k8s.v1.cni.cncf.io/network-status"
	statusJSON, exists := pod.Annotations[networkStatusAnnotation]
	if !exists {
		return psmoperatorv1alpha1.NetworkInterface{}, fmt.Errorf("network status annotation not found")
	}

	logger.V(1).Info("Processing network status annotation", 
		"Pod", pod.Name, 
		"Interface", macvlanSpec.NetworkAttachmentName,
		"StatusJSON", statusJSON)

	// Parse the network status JSON
	var networkStatuses []map[string]interface{}
	if err := json.Unmarshal([]byte(statusJSON), &networkStatuses); err != nil {
		return psmoperatorv1alpha1.NetworkInterface{}, fmt.Errorf("failed to parse network status: %w", err)
	}

	// Find the specific MACVLAN interface
	for _, status := range networkStatuses {
		interfaceName, _ := status["interface"].(string)

		// Match by interface name (e.g., "net1", "net2")
		if interfaceName == macvlanSpec.NetworkAttachmentName {
			logger.V(1).Info("Found matching interface in network status", 
				"Pod", pod.Name,
				"Interface", interfaceName,
				"Status", status)

			// Extract IP addresses - handle both string and array formats
			var firstIP string
			if ips, ok := status["ips"].([]interface{}); ok && len(ips) > 0 {
				if ip, ok := ips[0].(string); ok {
					// Remove CIDR notation if present (/24, /16, etc.)
					if strings.Contains(ip, "/") {
						firstIP = strings.Split(ip, "/")[0]
					} else {
						firstIP = ip
					}
				}
			}

			if firstIP == "" {
				logger.Error(fmt.Errorf("no IP found"), "No IP address found for interface", 
					"Pod", pod.Name, 
					"Interface", interfaceName,
					"IPs", status["ips"])
				continue
			}

			// Extract MAC address from annotation and convert to PSM format
			macAddr, _ := status["mac"].(string)
			convertedMAC := r.convertMACFormat(macAddr)

			// If no MAC in annotation, try to extract via exec
			if convertedMAC == "" || convertedMAC == "0000.0000.0000" {
				logger.Info("No MAC in annotation, attempting to extract via exec", 
					"Pod", pod.Name, 
					"Interface", interfaceName)
				
				execMAC, err := r.extractInterfaceMACViaExec(ctx, pod, interfaceName)
				if err != nil {
					logger.Error(err, "Failed to extract MAC via exec", 
						"Pod", pod.Name, 
						"Interface", interfaceName)
				} else {
					convertedMAC = r.convertMACFormat(execMAC)
				}
			}

			return psmoperatorv1alpha1.NetworkInterface{
				Name:        interfaceName,
				IPAddress:   firstIP,
				MACAddress:  convertedMAC,
				NetworkName: macvlanSpec.PsmNetworkName,
				Type:        "macvlan",
			}, nil
		}
	}

	return psmoperatorv1alpha1.NetworkInterface{}, 
		fmt.Errorf("MACVLAN interface %s not found in network status", macvlanSpec.NetworkAttachmentName)
}

// extractPrimaryInterfaceMAC extracts the primary interface MAC address via kubectl exec
func (r *PsmWorkloadRegistrationReconciler) extractPrimaryInterfaceMAC(ctx context.Context, pod *corev1.Pod) (string, error) {
	return r.extractInterfaceMACViaExec(ctx, pod, "eth0")
}

// extractInterfaceMACViaExec extracts MAC address for a specific interface via kubectl exec
func (r *PsmWorkloadRegistrationReconciler) extractInterfaceMACViaExec(
	ctx context.Context, 
	pod *corev1.Pod, 
	interfaceName string,
) (string, error) {
	logger := log.FromContext(ctx)
	
	// Note: This is a simplified version. In a real implementation, you would:
	// 1. Use the Kubernetes API to create an exec request
	// 2. Execute: cat /sys/class/net/{interface}/address
	// 3. Parse the result
	
	// For now, we'll return an empty string and log that exec would be needed
	logger.V(1).Info("MAC extraction via exec would be performed here", 
		"Pod", pod.Name, 
		"Interface", interfaceName,
		"Command", fmt.Sprintf("cat /sys/class/net/%s/address", interfaceName))
		
	// TODO: Implement actual kubectl exec logic here
	// This would require importing k8s.io/client-go/tools/remotecommand
	// and setting up the exec request properly
	
	return "", fmt.Errorf("exec-based MAC extraction not yet implemented")
}

// Enhanced extractPodLabels with better filtering
func (r *PsmWorkloadRegistrationReconciler) extractPodLabels(
	pod *corev1.Pod,
	labelMapping psmoperatorv1alpha1.LabelMappingSpec,
) map[string]string {
	extractedLabels := make(map[string]string)

	if labelMapping.IncludeAllLabels {
		// Include all pod labels, but exclude common Kubernetes system labels
		systemLabels := map[string]bool{
			"pod-template-hash":        true,
			"controller-revision-hash": true,
			"pod-template-generation":  true,
		}
		
		for k, v := range pod.Labels {
			if !systemLabels[k] {
				extractedLabels[k] = v
			}
		}
		
		// Add standard metadata
		extractedLabels["k8s.pod.name"] = pod.Name
		extractedLabels["k8s.pod.namespace"] = pod.Namespace
		extractedLabels["k8s.node.name"] = pod.Spec.NodeName
		
		return extractedLabels
	}

	// Include specific labels with mapping
	for podLabelKey, psmLabelKey := range labelMapping.SpecificLabels {
		if value, exists := pod.Labels[podLabelKey]; exists {
			extractedLabels[psmLabelKey] = value
		}
	}

	// Include labels by prefix
	for _, prefix := range labelMapping.LabelPrefixes {
		for k, v := range pod.Labels {
			if strings.HasPrefix(k, prefix) {
				extractedLabels[k] = v
			}
		}
	}

	// Always add basic metadata labels
	extractedLabels["k8s.pod.name"] = pod.Name
	extractedLabels["k8s.pod.namespace"] = pod.Namespace
	extractedLabels["k8s.node.name"] = pod.Spec.NodeName

	return extractedLabels
}

// listWorkloadsInPsm gets the list of workloads currently in PSM
func (r *PsmWorkloadRegistrationReconciler) listWorkloadsInPsm(
	ctx context.Context,
	client *http.Client,
	reg *psmoperatorv1alpha1.PsmWorkloadRegistration,
	username, password string,
) ([]string, error) {
	logger := log.FromContext(ctx)
	tenant := reg.Spec.PsmServer.Tenant
	if tenant == "" {
		tenant = "default"
	}

	listURL := fmt.Sprintf("https://%s/configs/workload/v1/tenant/%s/workloads", reg.Spec.PsmServer.Host, tenant)
	req, err := http.NewRequestWithContext(ctx, "GET", listURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create workload list request: %w", err)
	}

	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	req.Header.Add("Authorization", "Basic "+auth)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list workloads: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list workloads, status: %d, body: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read workloads response: %w", err)
	}

	// Parse the workload list response
	var workloadList struct {
		Items []struct {
			Meta struct {
				Name string `json:"name"`
			} `json:"meta"`
		} `json:"items"`
	}

	if err := json.Unmarshal(body, &workloadList); err != nil {
		logger.V(1).Info("Failed to parse workload list as JSON, trying as individual items")
		// PSM might return workloads as separate JSON objects, try to extract names differently
		return r.parseWorkloadNames(string(body)), nil
	}

	var workloadNames []string
	for _, item := range workloadList.Items {
		if item.Meta.Name != "" {
			workloadNames = append(workloadNames, item.Meta.Name)
		}
	}

	logger.V(1).Info("Listed workloads from PSM", "count", len(workloadNames), "names", workloadNames)
	return workloadNames, nil
}

// parseWorkloadNames extracts workload names from PSM response (fallback parser)
func (r *PsmWorkloadRegistrationReconciler) parseWorkloadNames(response string) []string {
	var names []string
	// Simple fallback: look for "name" fields in the response
	lines := strings.Split(response, "\n")
	for _, line := range lines {
		if strings.Contains(line, `"name"`) && strings.Contains(line, "testpod") {
			// Extract the name value - this is a simple parser
			parts := strings.Split(line, `"name":"`)
			if len(parts) > 1 {
				namePart := strings.Split(parts[1], `"`)[0]
				if namePart != "" {
					names = append(names, namePart)
				}
			}
		}
	}
	return names
}

func (r *PsmWorkloadRegistrationReconciler) loginToPsm(
	ctx context.Context,
	client *http.Client,
	reg *psmoperatorv1alpha1.PsmWorkloadRegistration,
	username, password string,
) error {
	logger := log.FromContext(ctx)

	tenant := reg.Spec.PsmServer.Tenant
	if tenant == "" {
		tenant = "default"
	}

	loginURL := fmt.Sprintf("https://%s/v1/login", reg.Spec.PsmServer.Host)
	loginPayload := map[string]string{
		"username": username,
		"password": password,
		"tenant":   tenant,
	}

	payloadBytes, err := json.Marshal(loginPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal login payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", loginURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("login failed with status %d: %s", resp.StatusCode, string(body))
	}

	logger.Info("Successfully logged in to PSM")
	return nil
}

// syncWorkloadToPsm handles the actual REST call to the PSM server.
func (r *PsmWorkloadRegistrationReconciler) syncWorkloadToPsm(
	ctx context.Context,
	client *http.Client,
	reg *psmoperatorv1alpha1.PsmWorkloadRegistration,
	pod *corev1.Pod,
	username, password, method string,
) error {
	logger := log.FromContext(ctx)

	// Get tenant from CRD or use default
	tenant := reg.Spec.PsmServer.Tenant
	if tenant == "" {
		tenant = "default"
	}

	// Use the correct PSM API path with tenant
	baseEndpoint := fmt.Sprintf("https://%s/configs/workload/v1/tenant/%s/workloads",
		reg.Spec.PsmServer.Host, tenant)

	var req *http.Request
	var err error

	if method == "POST" || method == "PUT" {
		// Extract network interfaces
		interfaces, err := r.extractNetworkInterfaces(ctx, pod, reg)
		if err != nil {
			logger.Error(err, "Failed to extract network interfaces", "Pod", pod.Name)
			// Continue with empty interfaces rather than failing completely
			interfaces = []psmoperatorv1alpha1.NetworkInterface{}
		}

		// Extract pod labels
		extractedLabels := r.extractPodLabels(pod, reg.Spec.LabelMapping)

		// Log extracted labels for debugging
		logger.Info("Extracted labels for pod", 
			"Pod", pod.Name, 
			"Labels", extractedLabels,
			"LabelCount", len(extractedLabels))

		templateData := struct {
			Pod            *corev1.Pod
			NetworkContext psmoperatorv1alpha1.NetworkContextSpec
			Interfaces     []psmoperatorv1alpha1.NetworkInterface
			Labels         map[string]string
		}{
			Pod:            pod,
			NetworkContext: reg.Spec.NetworkContext,
			Interfaces:     interfaces,
			Labels:         extractedLabels,
		}

		tmpl, err := template.New("payload").Parse(reg.Spec.PayloadTemplate)
		if err != nil {
			return fmt.Errorf("invalid payload template: %w", err)
		}
		var payload bytes.Buffer
		if err := tmpl.Execute(&payload, templateData); err != nil {
			return fmt.Errorf("failed to render payload template: %w", err)
		}

		endpoint := baseEndpoint

		// If POST and we get 409 (already exists), try PUT instead
		if method == "POST" {
			logger.Info("Sending workload to PSM", "Method", method, "Endpoint", endpoint, "Payload", payload.String())
			req, err = http.NewRequestWithContext(ctx, method, endpoint, &payload)
			if err != nil {
				return err
			}
			req.Header.Set("Content-Type", "application/json")
			auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
			req.Header.Add("Authorization", "Basic "+auth)

			resp, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("http request failed: %w", err)
			}
			defer resp.Body.Close()

			// If workload already exists (409), try PUT instead
			if resp.StatusCode == 409 {
				logger.Info("Workload already exists, trying PUT update", "Pod", pod.Name)
				putEndpoint := fmt.Sprintf("%s/%s", baseEndpoint, pod.Name)

				// Reset payload buffer
				payload.Reset()
				if err := tmpl.Execute(&payload, templateData); err != nil {
					return fmt.Errorf("failed to render payload template for PUT: %w", err)
				}

				logger.Info("Updating workload in PSM", "Method", "PUT", "Endpoint", putEndpoint, "Payload", payload.String())
				req, err = http.NewRequestWithContext(ctx, "PUT", putEndpoint, &payload)
				if err != nil {
					return err
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Add("Authorization", "Basic "+auth)

				resp, err = client.Do(req)
				if err != nil {
					return fmt.Errorf("http PUT request failed: %w", err)
				}
				defer resp.Body.Close()
			}

			// Check final response
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				body, _ := io.ReadAll(resp.Body)
				logger.Error(fmt.Errorf("PSM error"), "Failed PSM request",
					"statusCode", resp.StatusCode,
					"responseBody", string(body),
					"endpoint", req.URL.String())
				return fmt.Errorf("psm server returned non-success status code: %d, body: %s", resp.StatusCode, string(body))
			}

			logger.Info("Successfully synchronized workload with PSM", "Pod", pod.Name, "StatusCode", resp.StatusCode)
			return nil
		} else if method == "PUT" {
			endpoint = fmt.Sprintf("%s/%s", baseEndpoint, pod.Name)
			logger.Info("Updating workload in PSM", "Method", method, "Endpoint", endpoint, "Payload", payload.String())
			req, err = http.NewRequestWithContext(ctx, method, endpoint, &payload)
			if err != nil {
				return err
			}
			req.Header.Set("Content-Type", "application/json")
		}
	} else if method == "DELETE" {
		deleteEndpoint := fmt.Sprintf("%s/%s", baseEndpoint, pod.Name)
		logger.Info("Deleting workload from PSM", "Endpoint", deleteEndpoint)
		req, err = http.NewRequestWithContext(ctx, method, deleteEndpoint, nil)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("unsupported HTTP method: %s", method)
	}

	// Handle PUT and DELETE requests (POST is handled above)
	if method != "POST" {
		auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		req.Header.Add("Authorization", "Basic "+auth)

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("http request failed: %w", err)
		}
		defer resp.Body.Close()

		// Handle DELETE 404 as success - workload already gone
		if method == "DELETE" && resp.StatusCode == 404 {
			logger.Info("Workload already deleted from PSM", "Pod", pod.Name)
			return nil
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			// Read response body for more details
			body, _ := io.ReadAll(resp.Body)
			logger.Error(fmt.Errorf("PSM error"), "Failed PSM request",
				"statusCode", resp.StatusCode,
				"responseBody", string(body),
				"endpoint", req.URL.String())
			return fmt.Errorf("psm server returned non-success status code: %d, body: %s", resp.StatusCode, string(body))
		}

		logger.Info("Successfully synchronized workload with PSM", "Pod", pod.Name, "StatusCode", resp.StatusCode)
	}

	return nil
}

// Enhanced pod change detection predicate
func (r *PsmWorkloadRegistrationReconciler) podChangeDetectionPredicate() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			// Always process pod creation
			return true
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldPod := e.ObjectOld.(*corev1.Pod)
			newPod := e.ObjectNew.(*corev1.Pod)
			
			// Trigger reconciliation if:
			// 1. Pod phase changed
			if oldPod.Status.Phase != newPod.Status.Phase {
				return true
			}
			
			// 2. Pod IP changed
			if oldPod.Status.PodIP != newPod.Status.PodIP {
				return true
			}
			
			// 3. Labels changed
			if !r.labelsEqual(oldPod.Labels, newPod.Labels) {
				return true
			}
			
			// 4. Network annotations changed (MACVLAN interface changes)
			oldNetworkStatus := oldPod.Annotations["k8s.v1.cni.cncf.io/network-status"]
			newNetworkStatus := newPod.Annotations["k8s.v1.cni.cncf.io/network-status"]
			if oldNetworkStatus != newNetworkStatus {
				return true
			}
			
			// 5. Node assignment changed
			if oldPod.Spec.NodeName != newPod.Spec.NodeName {
				return true
			}
			
			return false
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			// Always process pod deletion
			return true
		},
	}
}

// labelsEqual compares two label maps
func (r *PsmWorkloadRegistrationReconciler) labelsEqual(old, new map[string]string) bool {
	if len(old) != len(new) {
		return false
	}
	
	for k, v := range old {
		if newV, exists := new[k]; !exists || v != newV {
			return false
		}
	}
	
	return true
}

// SetupWithManager sets up the controller with the Manager.
func (r *PsmWorkloadRegistrationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&psmoperatorv1alpha1.PsmWorkloadRegistration{}).
		Watches(
			&corev1.Pod{},
			handler.EnqueueRequestsFromMapFunc(r.findPsmRegistrationsForPod),
			builder.WithPredicates(r.podChangeDetectionPredicate()),
		).
		Complete(r)
}

// findPsmRegistrationsForPod finds all PsmWorkloadRegistration resources that match a given pod
func (r *PsmWorkloadRegistrationReconciler) findPsmRegistrationsForPod(ctx context.Context, pod client.Object) []reconcile.Request {
	logger := log.FromContext(ctx)

	// List all PsmWorkloadRegistration resources
	psmRegList := &psmoperatorv1alpha1.PsmWorkloadRegistrationList{}
	if err := r.List(ctx, psmRegList); err != nil {
		logger.Error(err, "Failed to list PsmWorkloadRegistrations")
		return []reconcile.Request{}
	}

	var requests []reconcile.Request
	for _, psmReg := range psmRegList.Items {
		// Check if the pod matches the selector
		selector, err := metav1.LabelSelectorAsSelector(&psmReg.Spec.PodSelector)
		if err != nil {
			logger.Error(err, "Failed to parse selector", "PsmWorkloadRegistration", psmReg.Name)
			continue
		}

		if selector.Matches(labels.Set(pod.GetLabels())) {
			// Pod matches this PsmWorkloadRegistration's selector
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      psmReg.Name,
					Namespace: psmReg.Namespace,
				},
			})
			logger.V(1).Info("Pod matches PsmWorkloadRegistration",
				"Pod", pod.GetName(),
				"PsmWorkloadRegistration", psmReg.Name)
		}
	}

	return requests
}
