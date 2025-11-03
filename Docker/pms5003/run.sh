#!/bin/bash
set -e
set -x

# Interwał w sekundach (15 minut = 900s)
INTERVAL=${INTERVAL:-900}

while true; do
    echo "Starting PMS5003 measurement... python3 /app/pmlog.py"

    python3 /app/pmlog.py \
        -p "$SERIAL_PORT" \
        --enable-pin "$ENABLE_PIN" \
        ${RESET_PIN:+--reset-pin "$RESET_PIN"} \
        --warmup-time "$WARMUP_TIME" \
        domoticz \
        -ip "$DOMOTICZ_IP" \
        -p "$DOMOTICZ_PORT" \
        --domoticz_user "$DOMOTICZ_USER" \
        --domoticz_password "$DOMOTICZ_PASSWORD" \
        -m oneshot \
        --measure-period "$INTERVAL" \
        --pm_1_idx "$PM_1_IDX" \
        --pm_25_idx "$PM_25_IDX" \
        --pm_10_idx "$PM_10_IDX" \
        --pm_1_percent_idx "$PM_1_PERCENT_IDX" \
        --pm_25_percent_idx "$PM_25_PERCENT_IDX" \
        --pm_10_percent_idx "$PM_10_PERCENT_IDX"

    echo "Sleeping for $INTERVAL seconds..."
    sleep "$INTERVAL"
done
