# Stage 1: Build binaries
FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build StateWeaver Core Engine
RUN CGO_ENABLED=0 GOOS=linux go build -buildvcs=false -ldflags="-w -s" -o /bin/stateweaver ./cmd/stateweaver

# Build Vulnerable Lab API
RUN CGO_ENABLED=0 GOOS=linux go build -buildvcs=false -ldflags="-w -s" -o /bin/vulnerable-api ./lab/vulnerable-api

# Build Secure Lab API
RUN CGO_ENABLED=0 GOOS=linux go build -buildvcs=false -ldflags="-w -s" -o /bin/secure-api ./lab/secure-api

# Target: StateWeaver CLI
FROM alpine:3.20 AS engine
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /workspace
COPY --from=builder /bin/stateweaver /usr/local/bin/stateweaver
ENTRYPOINT ["/usr/local/bin/stateweaver"]

# Target: Vulnerable Lab API
FROM alpine:3.20 AS vulnerable-lab
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /bin/vulnerable-api /usr/local/bin/vulnerable-api
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/vulnerable-api", "--port=8080"]

# Target: Secure Lab API
FROM alpine:3.20 AS secure-lab
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /bin/secure-api /usr/local/bin/secure-api
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/secure-api", "--port=8081"]

