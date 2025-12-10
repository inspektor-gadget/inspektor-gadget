package testutils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestContainerOptions(t *testing.T) {
	opts := defaultContainerOptions()

	require.Equal(t, DefaultContainerImage, opts.image)
	require.Equal(t, DefaultContainerImageTag, opts.imageTag)
	require.Empty(t, opts.seccompProfile, "Expected default seccompProfile to be empty")
	require.Nil(t, opts.sysctls, "Expected default sysctls to be nil")

	require.True(t, opts.logs, "Expected default logs to be true")
	require.True(t, opts.wait, "Expected default wait to be true")
	require.True(t, opts.removal, "Expected default removal to be true")
}
