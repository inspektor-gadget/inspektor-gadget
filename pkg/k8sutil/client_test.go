package k8sutil

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// isNoKubeErr returns true when err corresponds to a missing kubeconfig
// situation. Different Go/Kubernetes/backend configurations might surface
// either the sentinel ErrNoKubeConfig or an underlying os.IsNotExist error
// (e.g., when the kubeconfig file is absent). This helper centralizes the
// check so tests are robust to either behavior.

const (
	kubeconfigEnv = "KUBECONFIG"
	homeEnv       = "HOME"
)

func isNoKubeErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrNoKubeConfig) {
		return true
	}
	if os.IsNotExist(err) {
		return true
	}
	s := strings.ToLower(err.Error())
	if strings.Contains(s, "no kubeconfig") || strings.Contains(s, "no such file") || strings.Contains(s, "stat") {
		return true
	}
	return false
}

// TestNewKubeConfig_NoKubeconfig ensures that when there is no kubeconfig in
// the environment (KUBECONFIG unset and $HOME/.kube/config missing) the call
// to NewKubeConfig returns an error indicating no kubeconfig was found.
func TestNewKubeConfig_NoKubeconfig(t *testing.T) {
	origKube := os.Getenv(kubeconfigEnv)
	origHome := os.Getenv(homeEnv)
	t.Cleanup(func() {
		if origKube == "" {
			_ = os.Unsetenv(kubeconfigEnv)
		} else {
			_ = os.Setenv(kubeconfigEnv, origKube)
		}
		if origHome == "" {
			_ = os.Unsetenv(homeEnv)
		} else {
			_ = os.Setenv(homeEnv, origHome)
		}
	})

	// Ensure KUBECONFIG is not set so code tries in-cluster/home fallback.
	_ = os.Unsetenv(kubeconfigEnv)

	// Use a fresh temporary directory as HOME so that ~/.kube/config does not exist.
	tmpHome, err := os.MkdirTemp("", "k8sutil-no-kubeconfig-")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmpHome) })

	if err := os.Setenv(homeEnv, tmpHome); err != nil {
		t.Fatalf("failed to set HOME: %v", err)
	}

	// Make extra sure the file doesn't exist.
	cfgPath := filepath.Join(tmpHome, ".kube", "config")
	if _, err := os.Stat(cfgPath); err == nil {
		// If it exists for some reason, remove it.
		_ = os.Remove(cfgPath)
	}

	_, err = NewKubeConfig("", "")
	if err == nil {
		t.Fatalf("expected an error when kubeconfig is missing, got nil")
	}
	if !isNoKubeErr(err) {
		t.Fatalf("expected a 'no kubeconfig' related error, got: %v", err)
	}
}

// TestNewKubeConfig_HonorsKubeconfigEnvVar verifies that when KUBECONFIG is set
// to a (non-existent) path NewKubeConfig uses it and returns an error that
// indicates the file cannot be read/found.
func TestNewKubeConfig_HonorsKubeconfigEnvVar(t *testing.T) {
	origKube := os.Getenv(kubeconfigEnv)
	origHome := os.Getenv(homeEnv)
	t.Cleanup(func() {
		if origKube == "" {
			_ = os.Unsetenv(kubeconfigEnv)
		} else {
			_ = os.Setenv(kubeconfigEnv, origKube)
		}
		if origHome == "" {
			_ = os.Unsetenv(homeEnv)
		} else {
			_ = os.Setenv(homeEnv, origHome)
		}
	})

	// Point KUBECONFIG to a definitely-nonexistent file (do not create it).
	tmpCfg := filepath.Join(os.TempDir(), "inspektorgadget-nonexistent-kubeconfig.yaml")
	_ = os.Unsetenv(homeEnv) // ensure fallback to HOME does not interfere
	if err := os.Setenv(kubeconfigEnv, tmpCfg); err != nil {
		t.Fatalf("failed to set KUBECONFIG: %v", err)
	}

	_, err := NewKubeConfig("", "")
	if err == nil {
		t.Fatalf("expected an error when KUBECONFIG points to a non-existent file, got nil")
	}

	// Accept Either: os.IsNotExist (missing file) OR ErrNoKubeConfig for more tolerant implementations.
	if !os.IsNotExist(err) && !errors.Is(err, ErrNoKubeConfig) && !strings.Contains(strings.ToLower(err.Error()), "no such file") {
		t.Fatalf("expected file-not-found-related error or ErrNoKubeConfig, got: %v", err)
	}
}
