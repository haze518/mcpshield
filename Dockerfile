# ---- build stage --------------------------------------------------------
FROM golang:1.22-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/mcpshield ./cmd/mcpshield

# ---- final stage --------------------------------------------------------
# distroless/static: no shell, no package manager, minimal attack surface.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/mcpshield /mcpshield

EXPOSE 8080
ENTRYPOINT ["/mcpshield"]
CMD ["serve", "--config", "/etc/mcpshield/config.yaml"]
