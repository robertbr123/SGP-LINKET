FROM freeradius/freeradius-server:3.2

RUN apt-get update && apt-get install -y \
    freeradius-postgresql \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY config/ /etc/freeradius/3.0/

EXPOSE 1812/udp 1813/udp

CMD ["freeradius", "-X"]
