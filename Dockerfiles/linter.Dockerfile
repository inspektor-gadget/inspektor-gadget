# This version number must be kept in sync with CI workflow lint one.
ARG IMAGE=golangci/golangci-lint:v2.12.2@sha256:5cceeef04e53efe1470638d4b4b4f5ceefd574955ab3941b2d9a68a8c9ad5240
FROM ${IMAGE}

# The timeout specified below is used by 'make lint'. Please keep in sync with
# the timeout specified in .golangci.yml used by the CI.
ENTRYPOINT ["golangci-lint", "run", "--fix", "--timeout=10m0s"]
