ARG VERSION
FROM golangci/golangci-lint:${VERSION}
# libseccomp-dev is needed because we use libseccomp-golang which needs the C
# library.
RUN apt-get update \
	&& apt-get install -y libseccomp-dev
ENTRYPOINT golangci-lint run --fix
