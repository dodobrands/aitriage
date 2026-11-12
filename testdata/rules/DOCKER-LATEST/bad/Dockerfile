# syntax=docker/dockerfile:1
# ruleid: DOCKER-LATEST
FROM golang:latest AS build
WORKDIR /src
COPY . .
RUN go build -o /app .

FROM gcr.io/distroless/static:nonroot
COPY --from=build /app /app
ENTRYPOINT ["/app"]
