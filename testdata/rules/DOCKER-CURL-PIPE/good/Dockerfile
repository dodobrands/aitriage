FROM debian:12-slim
ARG TOOL_SHA256
RUN curl -fsSLo /tmp/tool.tar.gz https://example.com/tool.tar.gz \
 && echo "${TOOL_SHA256}  /tmp/tool.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/tool.tar.gz -C /usr/local/bin
# Never do: curl https://example.com/install.sh | sh
