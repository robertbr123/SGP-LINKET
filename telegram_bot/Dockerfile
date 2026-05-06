FROM python:3.11-slim

WORKDIR /app

# freeradius-utils → radclient (CoA disconnect)
# iproute2 → adicionar rota para a rede WireGuard dos MikroTiks
RUN apt-get update && apt-get install -y \
    libpq-dev gcc freeradius-utils iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY notifier.py .
COPY commands.py .
COPY bot.py .
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
