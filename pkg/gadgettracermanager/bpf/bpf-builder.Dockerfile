FROM fedora:26

ENV GOPATH /go

# vim-common is needed for xxd
# vim-minimal needs to be updated first to avoid an RPM conflict on man1/vim.1.gz
RUN dnf update -y vim-minimal && \
	dnf install -y llvm clang kernel-devel make binutils vim-common golang go-bindata ShellCheck git file

RUN curl -fsSLo shfmt https://github.com/mvdan/sh/releases/download/v1.3.0/shfmt_v1.3.0_linux_amd64 && \
	echo "b1925c2c405458811f0c227266402cf1868b4de529f114722c2e3a5af4ac7bb2  shfmt" | sha256sum -c && \
	chmod +x shfmt && \
	mv shfmt /usr/bin
RUN go get -u github.com/fatih/hclfmt

RUN mkdir -p /src /go
