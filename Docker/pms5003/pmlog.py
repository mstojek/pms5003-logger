#!/usr/bin/env python3
import sys
import os
import time
import signal
import struct
import logging
import argparse
from collections import namedtuple
from threading import Event
#import urllib.request, urllib.parse, urllib.error
import requests
from requests.auth import HTTPBasicAuth

from periphery import Serial
import lgpio

# ---------------- Logging ----------------
logging.basicConfig(
    level=logging.DEBUG,
    stream=sys.stderr,
    format="%(asctime)-15s %(levelname)-8s %(message)s"
)
log = logging.getLogger()

# ---------------- CLI args ----------------
parser = argparse.ArgumentParser(description="PMS5003 data logger")
parser.add_argument(
    "-p", "--serial-port", type=str, default="/dev/ttyS1",
    help="Serial port connected to the PMS5003 sensor")
parser.add_argument("--reset-pin", type=int, default=None,
                    help="GPIO number connected to the RESET signal")
parser.add_argument("--enable-pin", type=int, default=None,
                    help="GPIO number connected to the SET (enable) signal")
parser.add_argument("--warmup-time", type=int, default=30,
                    help="Seconds to wait before reading data")

subparsers = parser.add_subparsers(dest="cmd")

cmd_monitor_parser = subparsers.add_parser("monitor")
cmd_monitor_parser.add_argument("--measure-period", type=int, default=60 * 5,
                                help="Seconds between measurements")

cmd_oneshot_parser = subparsers.add_parser("oneshot")

cmd_domoticz_parser = subparsers.add_parser("domoticz")
cmd_domoticz_parser.add_argument("-ip", "--domoticz-ip", required=True,
                                 help="IP address of domoticz server")
cmd_domoticz_parser.add_argument("-p", "--domoticz-port", default=8080,
                                 help="Port of domoticz server")
cmd_domoticz_parser.add_argument("--domoticz_user", default="", help="Domoticz user")
cmd_domoticz_parser.add_argument("--domoticz_password", default="", help="Domoticz password")
cmd_domoticz_parser.add_argument("-m", "--mode", default="oneshot",
                                 choices=["oneshot", "monitor"],
                                 help="Monitor or oneshot mode")
cmd_domoticz_parser.add_argument("--measure-period", type=int, default=60 * 5,
                                 help="Seconds between measurements")
cmd_domoticz_parser.add_argument("--pm_1_idx", help="IDX of PM1")
cmd_domoticz_parser.add_argument("--pm_25_idx", help="IDX of PM2.5")
cmd_domoticz_parser.add_argument("--pm_10_idx", help="IDX of PM10")
cmd_domoticz_parser.add_argument("--pm_1_percent_idx", help="IDX of PM1 percent (100%% = 25 µg/m3)")
cmd_domoticz_parser.add_argument("--pm_25_percent_idx", help="IDX of PM2.5 percent (100%% = 25 µg/m3)")
cmd_domoticz_parser.add_argument("--pm_10_percent_idx", help="IDX of PM10 percent (100%% = 50 µg/m3)")

# ---------------- Packet structure ----------------
Packet = namedtuple("Packet", [
    "pm1_std", "pm25_std", "pm10_std", "pm01_atm", "pm2_5_atm",
    "pm10_atm", "count_03um", "count_05um", "count_1um",
    "count_2_5um", "count_5um", "count_10um"
])


# ---------------- PMS5003 class ----------------
class PMS5003:
    def __init__(self, port, enable_pin=None, reset_pin=None):
        self.port = Serial(port, 9600)
        self.enable_pin = enable_pin
        self.reset_pin = reset_pin
        self.stop = Event()

        self.chip = None
        self.h = None

        if enable_pin is not None or reset_pin is not None:
            # Open gpiochip0 (default)
            self.h = lgpio.gpiochip_open(0)

        if enable_pin is not None:
            lgpio.gpio_claim_output(self.h, enable_pin)
            lgpio.gpio_write(self.h, enable_pin, 0)
            log.info("Configured ENABLE pin %d as output", enable_pin)

        if reset_pin is not None:
            lgpio.gpio_claim_output(self.h, reset_pin)
            lgpio.gpio_write(self.h, reset_pin, 1)
            log.info("Configured RESET pin %d as output", reset_pin)

    def reset(self):
        if self.reset_pin is None:
            return
        log.info("Resetting sensor via GPIO %s", self.reset_pin)
        lgpio.gpio_write(self.h, self.reset_pin, 0)
        time.sleep(0.1)
        lgpio.gpio_write(self.h, self.reset_pin, 1)

    def enable(self):
        if self.enable_pin is None:
            return
        log.info("Enable sensor (via GPIO %s)", self.enable_pin)
        lgpio.gpio_write(self.h, self.enable_pin, 1)

    def disable(self):
        if self.enable_pin is None:
            return
        log.info("Disable sensor (via GPIO %s)", self.enable_pin)
        lgpio.gpio_write(self.h, self.enable_pin, 0)

    def discard_input(self):
        while self.port.input_waiting():
            self.port.read(4096, 0)

    def warmup(self, seconds):
        log.info("Warming up for %s seconds", seconds)
        self.stop.wait(seconds)
        self.discard_input()

    @staticmethod
    def packet_from_data(data):
        numbers = struct.unpack(">16H", data)
        csum = sum(data[:-2])
        if csum != numbers[-1]:
            log.warning("Bad packet checksum: %s / %s", data, csum)
            return None
        return Packet(*numbers[2:-2])

    def receive_one(self):
        while not self.stop.is_set():
            c = self.port.read(1)
            if not c or c != b"\x42":
                continue
            c = self.port.read(1, 0.1)
            if not c or c != b"\x4d":
                continue
            data = bytearray((0x42, 0x4d))
            data += self.port.read(30, 0.1)
            if len(data) != 32:
                continue
            packet = self.packet_from_data(data)
            if packet:
                return packet

    def close(self):
        if self.h:
            lgpio.gpiochip_close(self.h)


# ---------------- Domoticz ----------------
def send_http_request_to_domoticz(ip, port, user, password, idx, idx_value, timeout=10):

    url = f"http://{ip}:{port}/json.htm"
    params = {
        "type": "command",
        "param": "udevice",
        "nvalue": 0,
        "idx": idx,
        "svalue": idx_value
    }

    auth = None
    if user and password:
        auth = HTTPBasicAuth(user, password)

    try:
        if auth:
            resp = requests.get(url, params=params, auth=auth, timeout=timeout)

        # raise_for_status() podniesie wyjątek dla 4xx/5xx
        resp.raise_for_status()
        log.debug("Domoticz response: %s", resp.text.strip())
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else "?"
        log.error("HTTPError = %s, url=%s, params=%s", status, url, params)
    except requests.exceptions.Timeout:
        log.error("Timeout when contacting Domoticz %s:%s", ip, port)
    except requests.exceptions.RequestException as e:
        log.error("RequestException contacting Domoticz: %s", e)
    except Exception:
        import traceback
        log.error("Generic exception: %s", traceback.format_exc())

def report_to_domoticz(packet, args):
    if args.pm_1_idx:
        send_http_request_to_domoticz(args.domoticz_ip, args.domoticz_port, args.domoticz_user, args.domoticz_password, args.pm_1_idx, packet.pm01_atm)
    if args.pm_25_idx:
        send_http_request_to_domoticz(args.domoticz_ip, args.domoticz_port, args.domoticz_user, args.domoticz_password, args.pm_25_idx, packet.pm2_5_atm)
    if args.pm_10_idx:
        send_http_request_to_domoticz(args.domoticz_ip, args.domoticz_port, args.domoticz_user, args.domoticz_password, args.pm_10_idx, packet.pm10_atm)
    if args.pm_1_percent_idx:
        send_http_request_to_domoticz(args.domoticz_ip, args.domoticz_port, args.domoticz_user, args.domoticz_password, args.pm_1_percent_idx, packet.pm01_atm * 4)
    if args.pm_25_percent_idx:
        send_http_request_to_domoticz(args.domoticz_ip, args.domoticz_port, args.domoticz_user, args.domoticz_password, args.pm_25_percent_idx, packet.pm2_5_atm * 4)
    if args.pm_10_percent_idx:
        send_http_request_to_domoticz(args.domoticz_ip, args.domoticz_port, args.domoticz_user, args.domoticz_password, args.pm_10_percent_idx, packet.pm10_atm * 2)


# ---------------- Main loops ----------------
def run_monitor(sensor, args):
    start_at = time.time()
    sleep_period = args.measure_period - args.warmup_time
    sensor.enable()
    sensor.warmup(args.warmup_time)
    try:
        while not sensor.stop.is_set():
            packet = sensor.receive_one()
            if not packet:
                break
            log.info("@{:6.2f}\t{}".format(time.time() - start_at, packet))
            if args.cmd == "domoticz":
                report_to_domoticz(packet, args)
            if sleep_period > 0:
                sensor.disable()
                sensor.stop.wait(sleep_period)
                if sensor.stop.is_set():
                    break
                sensor.reset()
                sensor.enable()
                sensor.warmup(args.warmup_time)
            else:
                sensor.stop.wait(args.measure_period)
    except KeyboardInterrupt:
        log.info("Stopped by user.")
    finally:
        sensor.disable()
        sensor.close()


def run_oneshot(sensor, args):
    sensor.enable()
    sensor.warmup(args.warmup_time)
    try:
        packet = sensor.receive_one()
        log.info("%s", packet)
        if args.cmd == "domoticz":
            report_to_domoticz(packet, args)
    except KeyboardInterrupt:
        log.info("Stopped by user.")
    finally:
        sensor.disable()
        sensor.close()


def install_signal_handlers(sensor):
    def _sighandler(signum, frame):
        log.info("Got signal %s", signum)
        sensor.stop.set()
    signal.signal(signal.SIGINT, _sighandler)
    signal.signal(signal.SIGTERM, _sighandler)


# ---------------- Entry point ----------------
def main():
    args = parser.parse_args()
    sensor = PMS5003(args.serial_port, args.enable_pin, args.reset_pin)
    sensor.reset()
    install_signal_handlers(sensor)

    if args.cmd == "monitor":
        run_monitor(sensor, args)
    elif args.cmd == "oneshot":
        run_oneshot(sensor, args)
    elif args.cmd == "domoticz":
        if args.mode == "monitor":
            run_monitor(sensor, args)
        elif args.mode == "oneshot":
            run_oneshot(sensor, args)


if __name__ == "__main__":
    main()
