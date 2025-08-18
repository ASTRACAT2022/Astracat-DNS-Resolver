FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -o /dns-server .

FROM alpine:latest

WORKDIR /

COPY --from=builder /dns-server /dns-server

EXPOSE 53/udp

ENTRYPOINT ["/dns-server"]
