FROM node:20-alpine
WORKDIR /app
COPY . .
# USER node is set by the base image docs, but this file switches back.
USER root
CMD ["node", "server.js"]
