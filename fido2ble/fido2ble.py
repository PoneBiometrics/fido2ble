#!/usr/bin/env python

import argparse
import asyncio
import logging

from .vendored.dbus_fast import BusType
from .vendored.dbus_fast.aio import MessageBus

from .CTAPBLEDevice import CTAPBLEDevice, find_characteristics
from .CTAPHIDDevice import CTAPHIDDevice

FIDO_SERVICE_UUID = "0000fffd-0000-1000-8000-00805f9b34fb"
FIDO_CONTROL_POINT_UUID = "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb"
FIDO_STATUS_UUID = "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb"
FIDO_CONTROL_POINT_LENGTH_UUID = "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb"
FIDO_SERVICE_REVISION_BITFIELD_UUID = "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb"

DEVICE_INTERFACE = "org.bluez.Device1"
PROPERTIES_INTERFACE = "org.freedesktop.DBus.Properties"

fido_devices: dict[str, CTAPBLEDevice]
hid_devices: dict[str, CTAPHIDDevice]


async def properties_changed(interface, changed, invalidated):
    """Handles property changes for Bluetooth devices."""
    if interface == DEVICE_INTERFACE and "Paired" in changed:
        await update_fido_devices()


async def interfaces_added(path, interfaces, bus):
    """Handles new interfaces (e.g., new Bluetooth devices)."""
    if DEVICE_INTERFACE in interfaces:
        device1_interface = interfaces[DEVICE_INTERFACE]

        if "UUIDs" in device1_interface:
            for uuid in device1_interface["UUIDs"].value:
                if uuid == FIDO_SERVICE_UUID:
                    logging.info(f"Found new FIDO device: {path}")
                    # Get the specific device object
                    obj = bus.get_proxy_object(
                        "org.bluez", path, await bus.introspect("org.bluez", path)
                    )
                    props = obj.get_interface(PROPERTIES_INTERFACE)
                    props.on_properties_changed(properties_changed)


async def interfaces_removed(path, interfaces):
    """Handles removed interfaces (e.g., Bluetooth device lost/disconnected)."""
    if DEVICE_INTERFACE in interfaces:
        if path in fido_devices:
            fido_devices[path].remove_signal_handler()
            del fido_devices[path]
            hid_devices[path].device.destroy()
            del hid_devices[path]
            logging.info(f"Device Removed: {path}")


async def monitor_bluez():
    """Connects to BlueZ and listens for device events."""

    bus: MessageBus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    bluez_introspect = await bus.introspect("org.bluez", "/")

    dbus_proxy = bus.get_proxy_object("org.bluez", "/", bluez_introspect)
    manager = dbus_proxy.get_interface("org.freedesktop.DBus.ObjectManager")

    # Connect signal handlers
    # noinspection PyUnresolvedReferences
    manager.on_interfaces_added(
        lambda path, interfaces: asyncio.create_task(
            interfaces_added(path, interfaces, bus)
        )
    )
    # noinspection PyUnresolvedReferences
    manager.on_interfaces_removed(interfaces_removed)


async def create_device(device_path, dbus_managed_objects, bus) -> CTAPBLEDevice:
    device_proxy = bus.get_proxy_object(
        "org.bluez", device_path, await bus.introspect("org.bluez", device_path)
    )
    device1 = device_proxy.get_interface("org.bluez.Device1")
    cached = False
    for key in dbus_managed_objects:
        if key.startswith(device_path + "/"):
            cached = True
            break

    # Create a map to store characteristic paths
    characteristic_paths = {
        FIDO_CONTROL_POINT_UUID: None,
        FIDO_CONTROL_POINT_LENGTH_UUID: None,
        FIDO_STATUS_UUID: None,
    }

    await find_characteristics(device_path, dbus_managed_objects, characteristic_paths)
    control_point_path = characteristic_paths[FIDO_CONTROL_POINT_UUID]
    control_point_length_path = characteristic_paths[FIDO_CONTROL_POINT_LENGTH_UUID]
    status_path = characteristic_paths[FIDO_STATUS_UUID]
    return CTAPBLEDevice(
        device_proxy,
        device1,
        device_path,
        cached,
        control_point_path,
        control_point_length_path,
        status_path,
    )


async def find_fido() -> dict[str, CTAPBLEDevice]:
    bus: MessageBus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    bluez_introspect = await bus.introspect("org.bluez", "/")

    dbus_proxy = bus.get_proxy_object("org.bluez", "/", bluez_introspect)
    # noinspection PyUnresolvedReferences
    dbus_managed_objects = await dbus_proxy.get_interface(
        "org.freedesktop.DBus.ObjectManager"
    ).call_get_managed_objects()
    global fido_devices

    for device_path in dbus_managed_objects:
        if device_path in fido_devices:
            continue
        if "org.bluez.Device1" in dbus_managed_objects[device_path]:
            if dbus_managed_objects[device_path]["org.bluez.Device1"]["Paired"].value:
                if "UUIDs" in dbus_managed_objects[device_path]["org.bluez.Device1"]:
                    for uuid in dbus_managed_objects[device_path]["org.bluez.Device1"][
                        "UUIDs"
                    ].value:
                        if uuid == FIDO_SERVICE_UUID:
                            logging.info(f"Added {device_path} as FIDO device")
                            fido_devices[device_path] = await create_device(
                                device_path, dbus_managed_objects, bus
                            )
                elif (
                    "ServiceData"
                    in dbus_managed_objects[device_path]["org.bluez.Device1"]
                ):
                    if (
                        FIDO_SERVICE_UUID
                        in dbus_managed_objects[device_path]["org.bluez.Device1"][
                            "ServiceData"
                        ].value.keys()
                    ):
                        logging.info(f"Added {device_path} as FIDO device")
                        fido_devices[device_path] = await create_device(
                            device_path, dbus_managed_objects, bus
                        )
    return fido_devices


async def update_fido_devices():
    global fido_devices, hid_devices
    fido_devices = await find_fido()
    for fido_device in fido_devices:
        if fido_device not in hid_devices:
            hid = CTAPHIDDevice(fido_devices[fido_device])
            asyncio.create_task(hid.start())
            hid_devices[fido_device] = hid


async def start_system():
    global fido_devices, hid_devices
    fido_devices = {}
    hid_devices = {}
    await update_fido_devices()
    await monitor_bluez()
    await asyncio.Event().wait()


def main():
    parser = argparse.ArgumentParser(
        prog="fido2ble", description="connect with BLE FIDO2 devices"
    )
    parser.add_argument(
        "-l",
        "--log-level",
        default="warn",
        help="log level of service, either debug, info, warn or error",
    )
    parser.add_argument(
        "-u",
        "--uhid-log-level",
        default="error",
        help="log level of uhid device, either debug, info, warn or error",
    )

    args = parser.parse_args()

    loglevel = logging.WARNING
    if args.log_level == "debug":
        loglevel = logging.DEBUG
    elif args.log_level == "info":
        loglevel = logging.INFO
    elif args.log_level == "warn":
        loglevel = logging.WARNING
    elif args.log_level == "error":
        loglevel = logging.ERROR
    else:
        print(f"unrecognized loglevel {args.log_level}")
        exit(1)

    uhid_loglevel = logging.ERROR
    if args.uhid_log_level == "debug":
        uhid_loglevel = logging.DEBUG
    elif args.uhid_log_level == "info":
        uhid_loglevel = logging.INFO
    elif args.uhid_log_level == "warn":
        uhid_loglevel = logging.WARNING
    elif args.uhid_log_level == "error":
        uhid_loglevel = logging.ERROR
    else:
        print(f"unrecognized loglevel {args.uhid_log_level}")
        exit(1)
    logging.basicConfig(
        level=loglevel, format="%(asctime)s.%(msecs)03d %(message)s", datefmt="%I:%M:%S"
    )
    logging.getLogger("UHIDDevice").setLevel(uhid_loglevel)
    asyncio.run(start_system())


if __name__ == "__main__":
    main()
