ARG VERSION
FROM golangci/golangci-lint:${VERSION}
# libseccomp-dev is needed because we use libseccomp-golang which needs the C
# library.
RUN apt-get update \
	&& apt-get install -y libseccomp-dev

# The timeout specified below is used by 'make lint'. Please keep in sync with
# the timeout specified in .golangci.yml used by the CI.
ENTRYPOINT golangci-lint run --fix --timeout=10m0s
