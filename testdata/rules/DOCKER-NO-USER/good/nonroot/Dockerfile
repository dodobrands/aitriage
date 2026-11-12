FROM node:20-alpine
WORKDIR /app
COPY . .
RUN addgroup -S app && adduser -S app -G app
USER app
CMD ["node", "server.js"]
