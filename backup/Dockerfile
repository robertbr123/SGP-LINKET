FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# postgresql-client → pg_dump
# mongodb-database-tools → mongodump (instalado via apt da MongoDB)
# rclone → upload pra R2
# cron → agenda diária
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg cron tzdata \
        postgresql-client \
        rclone \
        unzip \
    && curl -fsSL https://www.mongodb.org/static/pgp/server-7.0.asc | gpg -o /usr/share/keyrings/mongodb-7.gpg --dearmor \
    && echo "deb [signed-by=/usr/share/keyrings/mongodb-7.gpg] http://repo.mongodb.org/apt/debian bookworm/mongodb-org/7.0 main" \
        > /etc/apt/sources.list.d/mongodb-org-7.0.list \
    && apt-get update && apt-get install -y --no-install-recommends mongodb-database-tools \
    && rm -rf /var/lib/apt/lists/*

ENV TZ=America/Manaus

WORKDIR /app

COPY backup.sh /app/backup.sh
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/backup.sh /app/entrypoint.sh

# Diretório local intermediário (apagado após upload)
RUN mkdir -p /backups

CMD ["/app/entrypoint.sh"]
