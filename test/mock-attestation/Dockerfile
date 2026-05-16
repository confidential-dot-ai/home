FROM golang:1.26 AS builder

WORKDIR /src
COPY go.mod .
COPY main.go .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /mock-attestation .

FROM gcr.io/distroless/static-debian12
COPY --from=builder /mock-attestation /mock-attestation
ENTRYPOINT ["/mock-attestation"]
