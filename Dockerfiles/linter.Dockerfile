ARG VERSION
FROM golangci/golangci-lint:${VERSION}

# The timeout specified below is used by 'make lint'. Please keep in sync with
# the timeout specified in .golangci.yml used by the CI.
ENTRYPOINT golangci-lint run --fix --timeout=10m0s
