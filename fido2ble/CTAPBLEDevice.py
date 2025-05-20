#!/usr/bin/env python
import asyncio
import logging
import struct
from functools import partial

from .vendored.dbus_fast import DBusError
from .vendored.dbus_fast import BusType
from .vendored.dbus_fast.aio import ProxyInterface, MessageBus

from .CMD import CTAPBLE_CMD


def notify_message(handler, interface_name, changed_properties, invalidated_properties):
    # Add check here for message length and read until done then close connection
    # Should bind this with USB as well as just direct translate.
    # Will most likely need read whole message to repackage as USB has different size
    if "Value" in changed_properties:
        handler(changed_properties["Value"].value)


FIDO_CONTROL_POINT_UUID = "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb"
FIDO_STATUS_UUID = "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb"
FIDO_CONTROL_POINT_LENGTH_UUID = "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb"
FIDO_SERVICE_REVISION_BITFIELD_UUID = "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb"


async def find_characteristics(device_path, objects, characteristic_paths):
    # Iterate through objects to find the characteristic with the target UUID
    if objects is None:
        bus: MessageBus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        bluez_introspect = await bus.introspect("org.bluez", "/")
        dbus_proxy = bus.get_proxy_object("org.bluez", "/", bluez_introspect)
        # noinspection PyUnresolvedReferences
        objects = await dbus_proxy.get_interface(
            "org.freedesktop.DBus.ObjectManager"
        ).call_get_managed_objects()

    for path, interfaces in objects.items():
        if path.startswith(device_path):
            if "org.bluez.GattCharacteristic1" in interfaces:
                characteristic_props = interfaces["org.bluez.GattCharacteristic1"]
                uuid = characteristic_props.get("UUID").value
                if uuid in characteristic_paths:
                    characteristic_paths[uuid] = path


DEFAULT_TIMEOUT = 3000  # milliseconds


class CTAPBLEDevice:
    device1_interface: ProxyInterface  # org.bluez.Device1
    device_id: str
    connected = False
    timeout = DEFAULT_TIMEOUT
    cached = False

    fido_control_point_path: str
    fido_control_point: ProxyInterface  # org.bluez.GattCharacteristic1
    fido_control_point_length_path: str
    fido_status_path: str
    fido_status: ProxyInterface  # org.bluez.GattCharacteristic1
    fido_status_notify_listen: (
        ProxyInterface  # org.freedesktop.DBus.Properties at fido status path
    )
    max_msg_size: int
    handler = None
    device_properties_interface: (
        ProxyInterface  # org.freedesktop.DBus.Properties at device top level
    )
    properties_changed_listener_active: bool = (
        False  # Flag to track if listener is active
    )

    def __init__(
        self,
        device_proxy,
        device1: ProxyInterface,
        device_id: str,
        cached: bool,
        control_point_path,
        control_point_length_path,
        status_path,
    ):
        self.device_proxy = device_proxy
        self.device1_interface = device1
        self.device_id = device_id
        self.max_msg_size = 0
        self.cached = cached
        self.fido_control_point_path = control_point_path
        self.fido_control_point_length_path = control_point_length_path
        self.fido_status_path = status_path
        self.connected = False
        self.device_properties_interface = self.device_proxy.get_interface(
            "org.freedesktop.DBus.Properties"
        )

    async def connect(self, handler):
        if self.connected:
            return self

        self.setup_signal_handler()
        if (
            self.max_msg_size == 0
        ):  # If we know Max Msg we have done this at least once. Don't want to redo it
            self.handler = partial(notify_message, handler)
            bus: MessageBus = await MessageBus(bus_type=BusType.SYSTEM).connect()
            logging.debug(f"Attempting to connect to {self.device_id}")
            # noinspection PyUnresolvedReferences
            await self.device1_interface.call_connect()

            # If the OS lacked data on this before we need to re-fetch data and reconnect but has to be a better way somehow
            if not self.cached:
                # noinspection PyUnresolvedReferences
                await self.device1_interface.call_disconnect()
                device_introspect = await bus.introspect("org.bluez", self.device_id)
                self.device_proxy = bus.get_proxy_object(
                    "org.bluez", self.device_id, device_introspect
                )
                self.device1_interface = self.device_proxy.get_interface(
                    "org.bluez.Device1"
                )
                self.cached = True
                # noinspection PyUnresolvedReferences
                await self.device1_interface.call_connect()

            if (
                self.fido_control_point_path is None
                or self.fido_control_point_length_path is None
                or self.fido_status_path is None
            ):
                characteristic_paths = {
                    FIDO_CONTROL_POINT_UUID: None,
                    FIDO_CONTROL_POINT_LENGTH_UUID: None,
                    FIDO_STATUS_UUID: None,
                }
                await find_characteristics(self.device_id, None, characteristic_paths)
                self.fido_control_point_path = characteristic_paths[
                    FIDO_CONTROL_POINT_UUID
                ]
                self.fido_control_point_length_path = characteristic_paths[
                    FIDO_CONTROL_POINT_LENGTH_UUID
                ]
                self.fido_status_path = characteristic_paths[FIDO_STATUS_UUID]

            control_point_length_proxy = bus.get_proxy_object(
                "org.bluez",
                self.fido_control_point_length_path,
                await bus.introspect("org.bluez", self.fido_control_point_length_path),
            )
            control_point_length = control_point_length_proxy.get_interface(
                "org.bluez.GattCharacteristic1"
            )

            status_proxy = bus.get_proxy_object(
                "org.bluez",
                self.fido_status_path,
                await bus.introspect("org.bluez", self.fido_status_path),
            )
            status_characteristic = status_proxy.get_interface(
                "org.bluez.GattCharacteristic1"
            )
            notify_properties = status_proxy.get_interface(
                "org.freedesktop.DBus.Properties"
            )

            control_point_proxy = bus.get_proxy_object(
                "org.bluez",
                self.fido_control_point_path,
                await bus.introspect("org.bluez", self.fido_control_point_path),
            )
            control_point = control_point_proxy.get_interface(
                "org.bluez.GattCharacteristic1"
            )
            # noinspection PyUnresolvedReferences
            self.max_msg_size = int.from_bytes(
                bytes(await control_point_length.call_read_value({})), "big"
            )
            logging.debug(f"size: {self.max_msg_size}")

            self.fido_control_point = control_point
            self.fido_status = status_characteristic
            self.fido_status_notify_listen = notify_properties
            self.connected = True
            await self.listen_to_notify()
        else:
            logging.debug(f"Device previously connected: {self.device_id}")
            await self.reconnect()

        self.keep_alive()
        logging.debug(f"Connection complete: {self.device_id}")
        return self

    async def reconnect(self):
        try:
            # noinspection PyUnresolvedReferences
            await self.device1_interface.call_connect()
        except Exception as error:
            logging.warning(f"Unable to reconnect to {self.device_id}, error: {error}")
        try:
            await self.listen_to_notify()
        except Exception as error:
            logging.warning(
                f"Unable to listen to notify when reconnecting to {self.device_id}, error: {error}"
            )

    async def disconnect(self):
        if self.connected:
            self.connected = False  # Has to be here to avoid sending messages while waiting for disconnect to finish
            logging.debug(f"Disconnecting: {self.device_id}")
            # noinspection PyUnresolvedReferences
            await self.fido_status.call_stop_notify()
            # noinspection PyUnresolvedReferences
            await self.device1_interface.call_disconnect()
        # noinspection PyUnresolvedReferences
        self.fido_status_notify_listen.off_properties_changed(self.handler)

    async def write_data(self, payload: bytes):
        try:
            while not self.connected:
                logging.debug("Waiting to connect")
                await self.reconnect()
            # noinspection PyUnresolvedReferences
            await self.fido_control_point.call_write_value(payload, {})
        except DBusError as error:
            logging.error(f"Unable to write to {self.device_id}, error: {error}")

    async def listen_to_notify(self):
        if self.connected:
            # noinspection PyUnresolvedReferences
            self.fido_status_notify_listen.on_properties_changed(self.handler)
            # noinspection PyUnresolvedReferences
            await self.fido_status.call_start_notify()

    async def send_ble_message(self, command: CTAPBLE_CMD, payload: bytes):
        logging.debug(
            f"ble tx: command={command.name} device={self.device_id} payload={payload.hex()}"
        )
        offset_start = 0
        seq = 0
        self.keep_alive()
        while offset_start < len(payload) or offset_start == 0:
            if seq == 0:
                capacity = self.max_msg_size - 3
                response = struct.pack(">BH", 0x80 | command, len(payload))
            else:
                capacity = self.max_msg_size - 1
                response = struct.pack(">B", seq - 1)
            response += payload[offset_start : (offset_start + capacity)]

            await self.write_data(response)

            offset_start += capacity
            seq += 1

    def get_connected_ble(self):
        if self.connected:
            return self

        return None

    def keep_alive(self):
        self.timeout = DEFAULT_TIMEOUT

    def properties_changed(self, interface, changed, invalidated):
        """Handles PropertiesChanged signal to update the connection state."""
        if interface == "org.bluez.Device1" and "Connected" in changed:
            self.connected = bool(changed["Connected"].value)
            logging.info(
                f"Device {self.device_id} connection status updated: {self.connected}"
            )

    def setup_signal_handler(self):
        """Attach signal handler to listen for connection status changes."""
        if self.properties_changed_listener_active:
            # Only set up the listener if it's not already active
            return

        if not self.device_properties_interface:
            logging.warning(
                f"Device properties interface not initialized for {self.device_id}"
            )
            self.device_properties_interface = self.device_proxy.get_interface(
                "org.freedesktop.DBus.Properties"
            )
        logging.debug(
            f"Setting up properties changed signal handler for {self.device_id}"
        )
        # noinspection PyUnresolvedReferences
        self.device_properties_interface.on_properties_changed(self.properties_changed)
        self.properties_changed_listener_active = True

    def remove_signal_handler(self):
        """Detach the signal handler to stop listening for property changes."""
        if not self.properties_changed_listener_active:
            # If no handler is active, there's nothing to remove
            return

        if not self.device_properties_interface:
            logging.warning(
                f"Device properties interface not initialized for {self.device_id}"
            )
            return

        logging.debug(
            f"Removing properties changed signal handler for {self.device_id}"
        )
        # Assuming the handler can be removed via the same interface object
        # The library might have an unsubscribe method or equivalent
        self.device_properties_interface.off_properties_changed(self.properties_changed)

        # Set the listener active flag to False
        self.properties_changed_listener_active = False
