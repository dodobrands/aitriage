#!/bin/sh
set -eu
# ruleid: DOCKER-SOCKET-MOUNT
docker run -d --name ci-agent -v /var/run/docker.sock:/var/run/docker.sock example/ci-agent:2.4
