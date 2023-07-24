FROM golang:alpine as builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/gossip /app/config.json ./
EXPOSE 6667/tcp
ENTRYPOINT ["./gossip"]
