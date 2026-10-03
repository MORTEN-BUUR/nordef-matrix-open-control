# NORDEF Matrix Open Control — MCP server image (stdio transport, no listening ports).
FROM python:3.11-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.11-slim
COPY --from=build /install /usr/local
RUN groupadd --system --gid 10001 nordef \
 && useradd --system --uid 10001 --gid nordef --home-dir /var/lib/nordef --shell /usr/sbin/nologin nordef \
 && install -d -m 0700 -o nordef -g nordef /var/lib/nordef \
 && install -d -m 0755 /etc/nordef
USER 10001:10001
ENV NORDEF_STATE_DIR=/var/lib/nordef \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
VOLUME ["/var/lib/nordef"]
# Mount /etc/nordef read-only with trusted-keys.json, license.key, license-keys.json.
ENTRYPOINT ["nordef-mcp"]
CMD ["--trusted-keys", "/etc/nordef/trusted-keys.json", \
     "--license", "/etc/nordef/license.key", \
     "--license-keys", "/etc/nordef/license-keys.json"]
