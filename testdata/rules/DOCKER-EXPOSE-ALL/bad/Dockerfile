FROM ubuntu:24.04
RUN apt-get update && apt-get install -y openssh-server
# ruleid: DOCKER-EXPOSE-ALL
EXPOSE 8080 22
CMD ["/usr/sbin/sshd", "-D"]
