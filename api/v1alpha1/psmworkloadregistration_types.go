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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SecretReference defines a reference to a Kubernetes Secret
type SecretReference struct {
	// Name of the secret
	// +kubebuilder:validation:Required
	Name string `json:"name"`
}

// PsmServerSpec defines the connection details for the PSM server
type PsmServerSpec struct {
	// Hostname or IP address of the PSM server
	// +kubebuilder:validation:Required
	Host string `json:"host"`

	// PSM tenant (optional, defaults to "default")
	// +kubebuilder:validation:Optional
	Tenant string `json:"tenant,omitempty"`

	// Reference to a Kubernetes Secret in the same namespace
	// that holds the username and password. The secret must contain
	// keys named 'username' and 'password'.
	// +kubebuilder:validation:Required
	CredentialsSecretRef SecretReference `json:"credentialsSecretRef"`
}

// MacvlanInterfaceSpec defines a specific MACVLAN interface to monitor
type MacvlanInterfaceSpec struct {
	// Network attachment name (e.g., "net1", "net2")
	// This corresponds to the interface name in the k8s.v1.cni.cncf.io/network-status annotation
	// +kubebuilder:validation:Required
	NetworkAttachmentName string `json:"networkAttachmentName"`

	// PSM network name for this interface
	// +kubebuilder:validation:Optional
	PsmNetworkName string `json:"psmNetworkName,omitempty"`

	// VLAN ID for this interface (preferred over network name)
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4094
	VlanID *int `json:"vlanId,omitempty"`

	// PSM Network Redirection - if true, ensure network exists in PSM
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	PsmNetworkRedirection bool `json:"psmNetworkRedirection,omitempty"`

	// PSM Virtual Router (VRF) for the network (required if psmNetworkRedirection=true)
	// +kubebuilder:validation:Optional
	PsmVirtualRouter string `json:"psmVirtualRouter,omitempty"`

	// Network subnet for PSM network creation (CIDR format, e.g., "192.168.22.0/24")
	// +kubebuilder:validation:Optional
	NetworkSubnet string `json:"networkSubnet,omitempty"`

	// Gateway IP for the PSM network
	// +kubebuilder:validation:Optional
	GatewayIP string `json:"gatewayIp,omitempty"`
}

// NetworkContextSpec defines network and interface configuration
type NetworkContextSpec struct {
	// Include the primary pod interface (eth0) in workload registration
	// +kubebuilder:validation:Optional
	IncludePrimaryInterface bool `json:"includePrimaryInterface,omitempty"`

	// Pod network name for primary interface (used when includePrimaryInterface=true)
	// +kubebuilder:validation:Optional
	PodNetworkName string `json:"podNetworkName,omitempty"`

	// List of MACVLAN interfaces to monitor and register
	// +kubebuilder:validation:Optional
	MacvlanInterfaces []MacvlanInterfaceSpec `json:"macvlanInterfaces,omitempty"`
}

// LabelMappingSpec defines how to handle pod labels when registering with PSM
type LabelMappingSpec struct {
	// Include all pod labels (default: false)
	// +kubebuilder:validation:Optional
	IncludeAllLabels bool `json:"includeAllLabels,omitempty"`

	// Map specific pod labels to PSM labels (key = pod label, value = PSM label)
	// +kubebuilder:validation:Optional
	SpecificLabels map[string]string `json:"specificLabels,omitempty"`

	// Include labels with specific prefixes
	// +kubebuilder:validation:Optional
	LabelPrefixes []string `json:"labelPrefixes,omitempty"`
}

// NetworkInterface represents a network interface on a workload
type NetworkInterface struct {
	// Interface name (e.g., "eth0", "net1", "net2")
	Name string `json:"name"`

	// IP address assigned to this interface
	IPAddress string `json:"ipAddress"`

	// MAC address in PSM format (aaaa.bbbb.cccc)
	MACAddress string `json:"macAddress"`

	// Network name this interface belongs to
	NetworkName string `json:"networkName,omitempty"`

	// Interface type (primary, macvlan)
	Type string `json:"type,omitempty"`
}

// PsmWorkloadRegistrationSpec defines the desired state of PsmWorkloadRegistration
type PsmWorkloadRegistrationSpec struct {
	// PSM server connection details
	// +kubebuilder:validation:Required
	PsmServer PsmServerSpec `json:"psmServer"`

	// Pod selector for which pods to manage
	// +kubebuilder:validation:Required
	PodSelector metav1.LabelSelector `json:"podSelector"`

	// Network context configuration
	// +kubebuilder:validation:Required
	NetworkContext NetworkContextSpec `json:"networkContext"`

	// Label mapping configuration
	// +kubebuilder:validation:Optional
	LabelMapping LabelMappingSpec `json:"labelMapping,omitempty"`

	// Template for the PSM API payload (Go template format)
	// The template has access to:
	// - .Pod: the Kubernetes Pod object
	// - .NetworkContext: the NetworkContextSpec
	// - .Interfaces: []NetworkInterface with extracted interfaces
	// - .Labels: map[string]string with extracted labels
	// +kubebuilder:validation:Required
	PayloadTemplate string `json:"payloadTemplate"`
}

// PsmWorkloadRegistrationStatus defines the observed state of PsmWorkloadRegistration
type PsmWorkloadRegistrationStatus struct {
	// List of pod names currently synchronized with PSM
	// +kubebuilder:validation:Optional
	SynchronizedPods []string `json:"synchronizedPods,omitempty"`

	// Number of active workloads
	// +kubebuilder:validation:Optional
	ActiveWorkloads int `json:"activeWorkloads,omitempty"`

	// Last synchronization time
	// +kubebuilder:validation:Optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// Current phase of the registration
	// +kubebuilder:validation:Optional
	Phase string `json:"phase,omitempty"`

	// Human-readable message about current status
	// +kubebuilder:validation:Optional
	Message string `json:"message,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="PSM Host",type=string,JSONPath=`.spec.psmServer.host`
//+kubebuilder:printcolumn:name="Active Workloads",type=integer,JSONPath=`.status.activeWorkloads`
//+kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
//+kubebuilder:printcolumn:name="Last Sync",type=date,JSONPath=`.status.lastSyncTime`
//+kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// PsmWorkloadRegistration is the Schema for the psmworkloadregistrations API
type PsmWorkloadRegistration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PsmWorkloadRegistrationSpec   `json:"spec,omitempty"`
	Status PsmWorkloadRegistrationStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// PsmWorkloadRegistrationList contains a list of PsmWorkloadRegistration
type PsmWorkloadRegistrationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PsmWorkloadRegistration `json:"items"`
}
