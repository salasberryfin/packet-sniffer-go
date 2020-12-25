FROM golang:1.12-alpine

# Install required packages for tcpdump to function
RUN apk add --no-cache git
RUN apk add --update gcc g++
RUN apk add libpcap-dev
RUN apk add tcpdump

# Current working directory
WORKDIR /app/packet-sniffer-go

# go.{mod,sum} files
COPY go.mod .
COPY go.sum .

# Prepare dependencies
RUN go mod download

# Copy project
COPY *.go .

# Build the Go app
RUN go build -o ./out/packet-sniffer-go .
