FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
# ruleid: DOCKER-SECRET-ARG
ARG NPM_TOKEN
RUN echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > .npmrc && npm ci && rm .npmrc
