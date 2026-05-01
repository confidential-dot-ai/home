FROM gcr.io/distroless/static:nonroot

COPY build/c8s /c8s
COPY build/attest-sev-snp /attest-sev-snp
COPY build/attest-tdx /attest-tdx

ENTRYPOINT ["/c8s", "cert-rotator"]
