package bpfstats

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// mockCloser implements io.Closer for testing
type mockCloser struct {
	closeFunc func() error
}

func (m *mockCloser) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

func TestEnableDisableBPFStats(t *testing.T) {
	// Store original EnableStats function and restore after tests
	originalEnableStats := enableStatsFn
	defer func() {
		enableStatsFn = originalEnableStats
	}()

	// Reset package state before each test
	resetState := func() {
		mutex.Lock()
		defer mutex.Unlock()
		refCnt = 0
		statsSock = nil
		method = MethodNone
	}

	tmpDir := t.TempDir()
	originalHostRoot := os.Getenv("HOST_ROOT")
	defer os.Setenv("HOST_ROOT", originalHostRoot)
	os.Setenv("HOST_ROOT", tmpDir)

	// Create mock /proc/sys/kernel/bpf_stats_enabled
	procDir := filepath.Join(tmpDir, "proc", "sys", "kernel")
	err := os.MkdirAll(procDir, 0755)
	require.NoError(t, err)
	statsFile := filepath.Join(procDir, "bpf_stats_enabled")

	t.Run("Enable with BPF_FUNC method", func(t *testing.T) {
		resetState()
		enableStatsFn = func(statsType uint32) (io.Closer, error) {
			return &mockCloser{}, nil
		}

		err := EnableBPFStats()
		assert.NoError(t, err)
		assert.Equal(t, MethodBPFFunc, GetMethod())
		assert.Equal(t, 1, refCnt)
		assert.NotNil(t, statsSock)

		// Second enable should increment refCnt
		err = EnableBPFStats()
		assert.NoError(t, err)
		assert.Equal(t, 2, refCnt)
	})

	t.Run("Enable with sysctl method", func(t *testing.T) {
		resetState()
		// Force BPF_FUNC to fail
		enableStatsFn = func(statsType uint32) (io.Closer, error) {
			return nil, unix.EINVAL
		}

		err := os.WriteFile(statsFile, []byte("0"), 0644)
		require.NoError(t, err)

		err = EnableBPFStats()
		assert.NoError(t, err)
		assert.Equal(t, MethodSysctl, GetMethod())
		assert.Equal(t, 1, refCnt)

		// Verify sysctl file was written
		content, err := os.ReadFile(statsFile)
		require.NoError(t, err)
		assert.Equal(t, "1", string(content))

		// Second enable should increment refCnt
		err = EnableBPFStats()
		assert.NoError(t, err)
		assert.Equal(t, 2, refCnt)
	})

	t.Run("Disable BPF_FUNC method", func(t *testing.T) {
		resetState()
		method = MethodBPFFunc
		refCnt = 2
		statsSock = &mockCloser{
			closeFunc: func() error {
				return nil
			},
		}

		// First disable should decrease refCnt
		err := DisableBPFStats()
		assert.NoError(t, err)
		assert.Equal(t, 1, refCnt)
		assert.NotNil(t, statsSock)

		// Second disable should clean up
		err = DisableBPFStats()
		assert.NoError(t, err)
		assert.Equal(t, 0, refCnt)
		assert.Nil(t, statsSock)
	})

	t.Run("Disable BPF_FUNC method with error", func(t *testing.T) {
		resetState()
		method = MethodBPFFunc
		refCnt = 1
		statsSock = &mockCloser{
			closeFunc: func() error {
				return io.ErrClosedPipe
			},
		}

		err := DisableBPFStats()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "disabling stat collection using BPF()")
		assert.Equal(t, 0, refCnt)
		assert.Nil(t, statsSock)
	})

	t.Run("Disable sysctl method", func(t *testing.T) {
		resetState()
		method = MethodSysctl
		refCnt = 2

		err := os.WriteFile(statsFile, []byte("1"), 0644)
		require.NoError(t, err)

		// First disable should only decrease refCnt
		err = DisableBPFStats()
		assert.NoError(t, err)
		assert.Equal(t, 1, refCnt)

		// Second disable should write to file
		err = DisableBPFStats()
		assert.NoError(t, err)
		assert.Equal(t, 0, refCnt)

		content, err := os.ReadFile(statsFile)
		require.NoError(t, err)
		assert.Equal(t, "0", string(content))
	})

	t.Run("Multiple disable calls beyond zero", func(t *testing.T) {
		resetState()
		method = MethodSysctl
		refCnt = 1

		// First disable
		err := DisableBPFStats()
		assert.NoError(t, err)
		assert.Equal(t, 0, refCnt)

		// Second disable should error
		err = DisableBPFStats()
		assert.Error(t, err)
		assert.Equal(t, "bpf stat collection already disabled", err.Error())
		assert.Equal(t, 0, refCnt)
	})

	t.Run("Error cases", func(t *testing.T) {
		t.Run("sysctl write error on enable", func(t *testing.T) {
			resetState()
			enableStatsFn = func(statsType uint32) (io.Closer, error) {
				return nil, unix.EINVAL
			}
			
			err := os.WriteFile(statsFile, []byte("0"), 0644)
			require.NoError(t, err)
			err = os.Chmod(statsFile, 0444)
			require.NoError(t, err)

			err = EnableBPFStats()
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "enabling stat collection")
		})

		t.Run("sysctl write error on disable", func(t *testing.T) {
			resetState()
			method = MethodSysctl
			refCnt = 1

			err := os.Chmod(statsFile, 0444)
			require.NoError(t, err)

			err = DisableBPFStats()
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "disabling stat collection using sysctl")
		})
	})

	t.Run("GetMethod", func(t *testing.T) {
		testCases := []struct {
			name           string
			initialMethod  BPFStatsMethod
			expectedMethod BPFStatsMethod
		}{
			{
				name:           "None",
				initialMethod:  MethodNone,
				expectedMethod: MethodNone,
			},
			{
				name:           "BPF_FUNC",
				initialMethod:  MethodBPFFunc,
				expectedMethod: MethodBPFFunc,
			},
			{
				name:           "Sysctl",
				initialMethod:  MethodSysctl,
				expectedMethod: MethodSysctl,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				resetState()
				method = tc.initialMethod
				assert.Equal(t, tc.expectedMethod, GetMethod())
			})
		}
	})
	
}