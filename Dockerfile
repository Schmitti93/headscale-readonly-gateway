FROM python@sha256:e5fa639e49b85986c4481e28faa2564b45aa8021413f31026c3856e5911618b1

ARG UID=65532
ARG GID=65532
RUN addgroup -S -g "$GID" gateway && adduser -S -D -H -u "$UID" -G gateway gateway
WORKDIR /app
COPY --chown=gateway:gateway src /app/src
ENV PYTHONPATH=/app/src \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER gateway:gateway
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD ["python", "-m", "headscale_readonly_gateway.healthcheck"]
ENTRYPOINT ["python", "-m", "headscale_readonly_gateway.gateway"]
