FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates
# ruleid: DOCKER-CURL-PIPE
RUN curl -fsSL https://example.com/install.sh | bash -
