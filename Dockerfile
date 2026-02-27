FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go index.html ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /fileshare .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /fileshare /fileshare
EXPOSE 8080
ENTRYPOINT ["/fileshare"]
