FROM golang:1.20-alpine

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build

EXPOSE 6667/tcp

CMD ["./gossip"]