FROM scratch
LABEL org.opencontainers.image.source="https://github.com/ferrum-edge/ferrum-edge"
LABEL org.opencontainers.image.description="Bounded native compiler-store data; never execute"
COPY cache.bin /cache.bin
CMD ["/never-execute-this-data-image"]
