FROM node:20-alpine
ARG NODE_ENV=production
ARG TOKEN_ENDPOINT_URL=https://auth.example.com/token
WORKDIR /app
COPY package*.json ./
RUN --mount=type=secret,id=npm_token NPM_TOKEN="$(cat /run/secrets/npm_token)" npm ci
