/*
Copyright 2021 The Kubernetes Authors.

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

package credentialprovider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	providerconfig "sigs.k8s.io/cloud-provider-azure/pkg/provider/config"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/golang-jwt/jwt/v5"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
	v1 "k8s.io/kubelet/pkg/apis/credentialprovider/v1"
)

const (
	// Kubernetes certificate path
	KubernetesCACertPath = "/etc/kubernetes/certs/ca.crt"
	// Kubelet kubeconfig path
	KubeletKubeconfigPath = "/var/lib/kubelet/kubeconfig"
	// ConfigMap name for identity binding mappings
	IdentityBindingConfigMapName      = "acr-identity-binding-mappings"
	IdentityBindingConfigMapNamespace = "kube-system"
)

// createKubeClient creates a Kubernetes client
// It tries in-cluster config first, then falls back to kubelet's kubeconfig
func createKubeClient() (kubernetes.Interface, error) {
	// Try in-cluster config first
	config, err := rest.InClusterConfig()
	if err != nil {
		klog.V(4).Infof("In-cluster config not available, trying kubelet kubeconfig: %v", err)

		// Fall back to kubelet's kubeconfig (for credential provider plugin running on nodes)
		config, err = clientcmd.BuildConfigFromFlags("", KubeletKubeconfigPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load kubeconfig from %s: %w", KubeletKubeconfigPath, err)
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes clientset: %w", err)
	}

	return clientset, nil
}

// identityBindingsTokenCredential implements azcore.TokenCredential interface
// using identity bindings token exchange
type identityBindingsTokenCredential struct {
	token       string
	identityKey string
	ibConfig    IdentityBindingsConfig
	endpoint    string
	transport   *http.Transport
	kubeClient  kubernetes.Interface
}

// tokenResponse represents the response from identity bindings token exchange
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
}

// createTransport creates an HTTP transport with custom CA
// The transport uses a custom dialer that resolves the SNI name to the configured API server IP
func createTransport(sniName string, apiServerIP string, caPool *x509.CertPool) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// reset Proxy to avoid using environment proxy settings
	transport.Proxy = nil

	// Custom dialer that resolves the SNI hostname to the fixed API server IP
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Extract port from addr (format is "host:port")
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse address %s: %w", addr, err)
		}

		// Always connect to the configured API server IP
		fixedAddr := net.JoinHostPort(apiServerIP, port)
		klog.V(5).Infof("Identity bindings: resolving %s to %s", addr, fixedAddr)

		dialer := &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		return dialer.DialContext(ctx, network, fixedAddr)
	}

	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS12, // #nosec G402
		}
	}
	transport.TLSClientConfig.ServerName = sniName
	// Explicitly set minimum TLS version to TLS 1.2 for security
	transport.TLSClientConfig.MinVersion = tls.VersionTLS12

	// Set custom CA pool if provided
	if caPool != nil {
		transport.TLSClientConfig.RootCAs = caPool
	}

	return transport
}

// getTransport provides the transport to use for the request
func (c *identityBindingsTokenCredential) getTransport() (*http.Transport, error) {
	// Return existing transport if already created
	if c.transport != nil {
		return c.transport, nil
	}

	// Read CA file
	b, err := os.ReadFile(KubernetesCACertPath)
	if err != nil {
		return nil, fmt.Errorf("read CA file %q: %w", KubernetesCACertPath, err)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("CA file %q is empty", KubernetesCACertPath)
	}

	// Create CA pool
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("parse CA file %q: no valid certificates found", KubernetesCACertPath)
	}

	// Create and cache transport
	c.transport = createTransport(c.ibConfig.SNIName, c.ibConfig.APIServerIP, caPool)

	return c.transport, nil
}

// GetToken retrieves an access token using identity bindings token exchange
func (c *identityBindingsTokenCredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	// The scope should be exactly one value in format "https://management.azure.com/.default"
	// or "https://containerregistry.azure.net/.default"
	if len(opts.Scopes) != 1 {
		return azcore.AccessToken{}, fmt.Errorf("expected exactly one scope, got %d", len(opts.Scopes))
	}

	scope := opts.Scopes[0]

	// Step 1: Get identity key
	identityKey := c.identityKey
	if identityKey == "" {
		return azcore.AccessToken{}, fmt.Errorf("identity key not found")
	}

	klog.V(4).Infof("Identity bindings: using identity key %q", identityKey)

	// Step 2: Get client ID from ConfigMap
	configMap, err := c.kubeClient.CoreV1().ConfigMaps(IdentityBindingConfigMapNamespace).Get(ctx, IdentityBindingConfigMapName, metav1.GetOptions{})
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("failed to get ConfigMap %s/%s: %w", IdentityBindingConfigMapNamespace, IdentityBindingConfigMapName, err)
	}

	// Parse the mappings JSON from ConfigMap
	mappingsJSON, exists := configMap.Data["mappings"]
	if !exists {
		return azcore.AccessToken{}, fmt.Errorf("mappings key not found in ConfigMap %s/%s", IdentityBindingConfigMapNamespace, IdentityBindingConfigMapName)
	}

	// Parse the JSON mappings
	var mappings map[string]string
	if err := json.Unmarshal([]byte(mappingsJSON), &mappings); err != nil {
		return azcore.AccessToken{}, fmt.Errorf("failed to parse mappings JSON from ConfigMap: %w", err)
	}

	// Lookup clientID for the identity key from mappings
	clientID, exists := mappings[identityKey]
	if !exists {
		return azcore.AccessToken{}, fmt.Errorf("identity key %q not found in ConfigMap %s/%s mappings", identityKey, IdentityBindingConfigMapNamespace, IdentityBindingConfigMapName)
	}

	if clientID == "" {
		return azcore.AccessToken{}, fmt.Errorf("client ID for identity key %q is empty in ConfigMap", identityKey)
	}

	klog.V(4).Infof("Identity bindings: resolved client ID %q for identity %q", clientID, identityKey)

	// Step 3: Exchange token using saved SA token
	formData := url.Values{}
	formData.Set("grant_type", "client_credentials")
	formData.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	formData.Set("scope", scope)
	formData.Set("client_assertion", c.token) // Use saved SA token directly
	formData.Set("client_id", clientID)

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", c.endpoint, strings.NewReader(formData.Encode()))
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	klog.V(4).Infof("Requesting token from identity bindings endpoint: %s with scope: %s", c.endpoint, scope)

	// Get transport (handles CA rotation)
	transport, err := c.getTransport()
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("failed to get transport: %w", err)
	}

	// Execute request
	httpClient := &http.Client{Transport: transport}
	resp, err := httpClient.Do(req)
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("failed to execute token request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return azcore.AccessToken{}, fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var tokenResp tokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return azcore.AccessToken{}, fmt.Errorf("failed to parse token response: %w", err)
	}

	expiresOn := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	klog.V(4).Infof("Successfully obtained token from identity bindings, expires at: %s", expiresOn)

	return azcore.AccessToken{
		Token:     tokenResp.AccessToken,
		ExpiresOn: expiresOn,
	}, nil
}

func GetIdentityBindingsTokenCredential(req *v1.CredentialProviderRequest, config *providerconfig.AzureClientConfig, ibConfig IdentityBindingsConfig) (azcore.TokenCredential, error) {
	klog.V(2).Infof("Using identity bindings token credential for image %s", req.Image)

	// Get SNI name from config
	sniName := ibConfig.SNIName
	if sniName == "" {
		return nil, fmt.Errorf("SNI name not provided in identity bindings config")
	}

	// Get API server IP from config
	apiServerIP := ibConfig.APIServerIP
	if apiServerIP == "" {
		return nil, fmt.Errorf("API server IP not provided in identity bindings config")
	}

	// Get service account token
	token := req.ServiceAccountToken
	if token == "" {
		return nil, fmt.Errorf("service account token not found in request")
	}

	// Parse JWT to extract identity key from sub claim
	parsedToken, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse service account token: %w", err)
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("failed to extract claims from service account token")
	}

	sub, err := claims.GetSubject()
	if err != nil {
		return nil, fmt.Errorf("failed to get subject from token claims: %w", err)
	}

	// Extract identity key from subject (format: "system:serviceaccount:namespace:serviceaccount")
	const subPrefix = "system:serviceaccount:"
	if !strings.HasPrefix(sub, subPrefix) {
		return nil, fmt.Errorf("invalid subject format in token, expected prefix %q, got %q", subPrefix, sub)
	}

	identityKey := strings.TrimPrefix(sub, subPrefix)
	if identityKey == "" {
		return nil, fmt.Errorf("identity key is empty after removing prefix from subject")
	}

	klog.V(4).Infof("Identity bindings: extracted identity key %q from service account token", identityKey)

	// Build endpoint URL
	endpoint := "https://" + sniName

	// Initialize Kubernetes client
	kubeClient, err := createKubeClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	return &identityBindingsTokenCredential{
		token:       token,
		identityKey: identityKey,
		ibConfig:    ibConfig,
		endpoint:    endpoint,
		kubeClient:  kubeClient,
	}, nil
}
