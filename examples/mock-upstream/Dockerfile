# ---- build stage --------------------------------------------------------
FROM golang:1.22-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/mock-upstream ./examples/mock-upstream

# ---- final stage --------------------------------------------------------
# alpine: small image with wget available for health checks.
FROM alpine:3.20

RUN adduser -D -u 1000 app
USER app

COPY --from=builder /out/mock-upstream /mock-upstream

EXPOSE 9090
ENTRYPOINT ["/mock-upstream"]
