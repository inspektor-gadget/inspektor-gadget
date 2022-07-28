FROM ghcr.io/colinianking/stress-ng:master
RUN adduser --disabled-password --gecos "" --no-create-home foo
USER foo
WORKDIR /tmp
ENTRYPOINT sh -c "stress-ng --exec $(nproc) --exec-method execve --timeout 1s --metrics-brief"