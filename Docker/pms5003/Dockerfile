FROM python:3.11-slim

# Instalacja zależności systemowych
RUN apt-get update && apt-get install -y \
    python3-dev \
    gcc \
    g++ \
    libgpiod3 \
    && pip install --no-cache-dir lgpio python-periphery requests \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Kopiowanie plików do kontenera
COPY pmlog.py /app/pmlog.py
COPY run.sh /app/run.sh

RUN chmod +x /app/run.sh

# Domyślne zmienne środowiskowe
ENV SERIAL_PORT=/dev/serial0
ENV ENABLE_PIN=24
ENV WARMUP_TIME=50
ENV MEASURE_PERIOD=900 
ENV DOMOTICZ_IP=127.0.0.1
ENV DOMOTICZ_PORT=8080
ENV PM1_IDX=2
ENV PM25_IDX=3
ENV PM10_IDX=4
ENV PM1_PERCENT_IDX=5
ENV PM25_PERCENT_IDX=6
ENV PM10_PERCENT_IDX=7

ENTRYPOINT ["/app/run.sh"]

