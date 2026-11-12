FROM golang:1.23-alpine AS build
WORKDIR /src
COPY . .
RUN go build -o /api ./cmd/api

# ruleid: DOCKER-LATEST
FROM alpine:latest
COPY --from=build /api /api
USER 65532
ENTRYPOINT ["/api"]
