FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    freeradius \
    freeradius-postgresql \
    freeradius-utils \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY config/ /etc/freeradius/3.0/

# Copia scripts auxiliares (ex.: forward de accounting ao SGP)
RUN mkdir -p /etc/freeradius/3.0/scripts
COPY scripts/ /etc/freeradius/3.0/scripts/
RUN chmod +x /etc/freeradius/3.0/scripts/*.sh

RUN chown -R freerad:freerad /etc/freeradius/3.0/

EXPOSE 1812/udp 1813/udp

CMD ["freeradius", "-f", "-l", "stdout"]
