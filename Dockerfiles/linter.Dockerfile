# This version number must be kept in sync with CI workflow lint one.
ARG IMAGE=golangci/golangci-lint:v2.1.6@sha256:568ee1c1c53493575fa9494e280e579ac9ca865787bafe4df3023ae59ecf299b
FROM ${IMAGE}

# The timeout specified below is used by 'make lint'. Please keep in sync with
# the timeout specified in .golangci.yml used by the CI.
ENTRYPOINT ["golangci-lint", "run", "--fix", "--timeout=10m0s"]
