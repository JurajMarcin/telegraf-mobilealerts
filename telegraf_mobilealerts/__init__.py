from argparse import ArgumentParser
from dataclasses import field
import logging
import re
from struct import pack
from sys import stderr
from time import time, time_ns
from typing import Any

from aiohttp import web
from mobilealerts.sensor import Sensor
from tomlconfig import configclass, parse


@configclass
class Config:
    debug: bool = False
    allow_gateways: list[str] = field(default_factory=list)
    allow_sensors: list[str] = field(default_factory=list)


parser = ArgumentParser("Visu")
parser.add_argument("--debug", help="show debug output on stderr",
                    action="store_true", default=False)
parser.add_argument("--config", help="load config from the file CONFIG",
                    default="/etc/telegraf_mobilealerts.toml")
args = parser.parse_args()


_config = parse(Config, args.config)
if args.debug:
    _config.debug = True
_logger = logging.getLogger(__name__)
_log_handler = logging.StreamHandler(stderr)
_log_handler.setFormatter(
    logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"),
)
_logger.addHandler(_log_handler)
_logger.setLevel(logging.DEBUG if _config.debug else logging.INFO)


async def _influx_print(field: str, value: Any, *tags: tuple[str, str]) \
        -> None:
    value = f"\"{value}\"" if isinstance(value, str) else repr(value)
    print(",".join(["mobilealerts",
                    *(f"{tag_k:s}={str(tag_v)}" for tag_k, tag_v in tags)]),
          f"{field:s}={value} {time_ns()}")


async def _device_seen(device_type: str, device_id: str) -> None:
    await _influx_print("status", 1, ("device_type", device_type),
                        ("device_id", device_id))


async def _handle_device_setup(payload: bytes, ident: list[str]) -> None:
    if len(payload) == 15 and payload[5:11].hex().upper() == ident[1]:
        await _device_seen("gateway", ident[1])
    else:
        _logger.warning("Invalid payload len %r or payload ident %r != %r",
                        len(payload), payload[5:11].hex().upper(), ident[1])


async def _handle_sensor_update(payload: bytes, checksum: int,
                                ident: list[str]) -> None:
    payload_checkum = 0
    for b in payload:
        payload_checkum += b
    payload_checkum &= 0x7F
    if checksum != payload_checkum:
        _logger.error("Invalid checksum of payload from %r", ident[1])
        return
    sensor_id = payload [6:12].hex().upper()
    if _config.allow_sensors and sensor_id not in _config.allow_sensors:
        _logger.info("Ignoring request from sensor %r", sensor_id)
        return
    await _device_seen("sensor", sensor_id)
    sensor = Sensor(None, sensor_id)
    sensor.parse_packet(payload)
    _logger.debug(sensor.str_utc())
    await _influx_print("battery", 1 if not sensor.low_battery else 0,
                        ("gateway_id", ident[1]),
                        ("sensor_id", sensor_id))
    for measurement in sensor.measurements:
        await _influx_print(str(measurement.type).split('.')[1].lower(),
                            measurement.value,
                            ("gateway_id", ident[1]),
                            ("sensor_id", sensor_id),
                            ("measurement_name",
                             re.sub(r"\s+", "_", measurement.name.lower())),
                            ("measurement_index", measurement.index))


async def _handle_device_update(payload: bytes, ident: list[str]) -> None:
    pos = 0

    while pos + 64 <= len(payload):
        await _handle_sensor_update(payload[pos : pos + 63], payload[pos + 63],
                                    ident)
        pos += 64


async def _get_response(request: web.BaseRequest) -> web.StreamResponse:
    response = web.StreamResponse(
        headers={
            "Content-Type": "application/octet-stream",
            "Content-Length": "24",
            "Connection": "close",
        }
    )
    await response.prepare(request)
    content = pack(">IIIIII", 1, 0, int(time()), 1, 0x1761D480, 1)
    await response.write_eof(content)
    return response


async def _handler(request: web.BaseRequest) -> web.StreamResponse:
    response = await _get_response(request)
    ident = request.headers.get("HTTP_IDENTIFY", "").split(":")
    if len(ident) != 3:
        _logger.warning("Got request with invalid HTTP_IDENTIFY from %r",
                        request.remote)
        return response
    _logger.debug("Got request %r from device %r", ident[2], ident[1])
    if _config.allow_gateways and ident[1] not in _config.allow_gateways:
        _logger.info("Ignoreing request from %r", ident[1])
        return response
    payload = await request.content.read(int(
        request.headers["Content-Length"],
    ))
    if ident[2] == "00":
        await _handle_device_setup(payload, ident)
    elif ident[2] == "C0":
        await _handle_device_update(payload, ident)
    else:
        _logger.warning("Got invalid request type %r from device %r", ident[2],
                        ident[1])
    return response


def main() -> None:
    app = web.Application()
    app.add_routes([web.put("/gateway/put", _handler)])
    web.run_app(app, host="192.168.88.17", port=80,
                print=lambda *args, **kwargs: print(*args, **kwargs,
                                                    file=stderr))


if __name__ == "__main__":
    main()
