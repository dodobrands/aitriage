# FROM golang:latest was replaced with a pinned version.
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY . .
RUN go build -o /app .

FROM gcr.io/distroless/static:nonroot
COPY --from=build /app /app
ENTRYPOINT ["/app"]
