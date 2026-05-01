FROM gcr.io/distroless/static-debian12

COPY build/c8s /c8s

EXPOSE 8080
VOLUME ["/data"]

ENTRYPOINT ["/c8s", "assam"]
