FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml README.md ./
COPY osgate/ ./osgate/
RUN pip install --no-cache-dir . && useradd --system --uid 10001 --home /nonexistent osgate && mkdir -p /data /ssh && chown -R osgate:osgate /data
USER osgate
EXPOSE 5812 1080
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 CMD ["python", "-m", "osgate.healthcheck"]
ENTRYPOINT ["osgate"]
CMD ["start"]
