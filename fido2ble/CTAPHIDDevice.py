import asyncio
import logging
import struct
import sys
from random import randint

from .vendored import uhid
from .vendored.dbus_fast import DBusError

from .CMD import CTAPHID_CAPABILITIES, CTAPHID_CMD, CTAPBLE_CMD
from .CTAPBLEDevice import CTAPBLEDevice

# noinspection SpellCheckingInspection
CTAPHID_BROADCAST_CHANNEL = 0xFFFFFFFF


class CTAPHIDDevice:
    device: uhid.UHIDDevice
    ble_device: CTAPBLEDevice
    channels_to_state: dict[int, bytes] = {}
    active_tasks: list = []
    timeout_task = None
    active_channel: int

    hid_packet_size: int = 64
    channel: int = 0
    hid_command: CTAPHID_CMD = CTAPHID_CMD.CANCEL
    hid_buffer: bytes = b""
    hid_total_length = 0
    hid_seq = -1

    fidoControlPointLength: int = 60
    ble_command: CTAPBLE_CMD = CTAPBLE_CMD.CANCEL
    ble_buffer: bytes = b""
    ble_total_length = 0
    ble_seq = -1

    reference_count = 0
    """Number of open handles to the device: clear state when it hits zero."""

    def __init__(self, ble_device):
        # This could then also include the proper name, VID, PID and so on
        self.ble_device = ble_device
        addr = ble_device.device_id.split("_")[1:]
        vid = int("".join(addr[0:2]), 16)
        pid = int("".join(addr[2:4]), 16)
        name = "PONE Fido2BLE Proxy %s" % (":".join(addr))
        try:
            self.device = uhid.UHIDDevice(
                vid,
                pid,
                name,
                report_descriptor=[
                    0x06,
                    0xD0,
                    0xF1,  # Usage Page (FIDO alliance HID usage page)
                    0x09,
                    0x01,  # Usage (U2FHID usage for top-level collection)
                    0xA1,
                    0x01,  # Collection (Application)
                    0x09,
                    0x20,  # Usage (Raw IN data report)
                    0x15,
                    0x00,  # Logical Minimum (0)
                    0x26,
                    0xFF,
                    0x00,  # Logical Maximum (255)
                    0x75,
                    0x08,  # Report Size (8)
                    0x95,
                    0x40,  # Report Count (64)
                    0x81,
                    0x02,  # Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
                    0x09,
                    0x21,  # Usage (Raw OUT data report)
                    0x15,
                    0x00,  # Logical Minimum (0)
                    0x26,
                    0xFF,
                    0x00,  # Logical Maximum (255)
                    0x75,
                    0x08,  # Report Size (8)
                    0x95,
                    0x40,  # Report Count (64)
                    0x91,
                    0x02,  # Output (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)
                    0xC0,  # End Collection
                ],
                backend=uhid.AsyncioBlockingUHID,
                physical_name="Test Device",
            )
        except PermissionError:
            print("Not enough permissions to access /dev/uhid. Rerun as root?")
            sys.exit(1)

        self.device.receive_open = self.process_open
        self.device.receive_close = self.process_close
        self.device.receive_output = self.process_process_hid_message

    async def start(self):
        await self.device.wait_for_start_asyncio()

    def process_open(self):
        self.reference_count += 1

    def process_close(self):
        self.reference_count -= 1

    def process_process_hid_message(
        self, buffer: list[int], report_type: uhid._ReportType
    ) -> None:
        # output_report = buffer[0]
        received_data = bytes(buffer[1:])
        channel, cmd_or_seq = struct.unpack(">IB", received_data[0:5])
        # continuation = cmd_or_seq & 0x80 != 0
        cmd_or_seq = cmd_or_seq & 0x7F
        try:
            if channel == CTAPHID_BROADCAST_CHANNEL and cmd_or_seq == CTAPHID_CMD.INIT:
                self.active_tasks.append(
                    asyncio.create_task(
                        self.handle_init(channel, received_data[7 : 7 + 8])
                    )
                )
            else:
                self.handle_hid_message(channel, received_data[4:])
        except BaseException as error:
            logging.warning(f"Error: {error}")

    async def handle_init(self, channel, buffer: bytes):
        logging.debug(
            f"hid init: channel={'%X' % channel} buffer={buffer} device={self.device}"
        )
        # Block if there is an active channel???
        if channel == CTAPHID_BROADCAST_CHANNEL and len(buffer) == 8:
            # https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#usb-channels
            new_channel = randint(1, CTAPHID_BROADCAST_CHANNEL - 1)

            try:
                await self.ble_device.connect(self.handle_ble_message)
            except asyncio.CancelledError as cancelError:
                logging.warning(
                    f"Unable to connect to {self.ble_device.device_id}, cancelled: {cancelError}"
                )
                # Failed to connect, we abort now
                return
            except DBusError as dbusError:
                logging.warning(
                    f"Unable to connect to {self.ble_device.device_id}, error: {dbusError}"
                )
                # Failed to connect, we abort now
                return
            self.channel = new_channel
            await self.send_init_reply(buffer, CTAPHID_BROADCAST_CHANNEL)
            logging.debug(f"Init complete for {self.ble_device.device_id}")

            self.active_channel = new_channel
            self.channels_to_state[new_channel] = buffer
        elif buffer == self.channels_to_state[channel]:
            await self.send_init_reply(buffer, self.channel)
            # ble_device = self.ble_device

            # if ble_device is None:
            #    return None

            try:
                await self.ble_device.connect(self.handle_ble_message)
            except asyncio.CancelledError as cancelError:
                logging.warning(
                    f"Unable to connect to {self.ble_device.device_id}, cancelled: {cancelError}"
                )
                # Failed to connect, we abort now
                return
            except DBusError as dbusError:
                logging.warning(
                    f"Unable to connect to {self.ble_device.device_id}, error: {dbusError}"
                )
                # Failed to connect, we abort now
                return
            self.active_channel = channel
        self.setup_timeout()

    async def send_init_reply(self, nonce: bytes, channel: int):
        await self.send_hid_message(
            CTAPHID_CMD.INIT,
            struct.pack(
                ">8sIBBBBB",
                nonce,
                self.channel,
                2,  # protocol version, currently fixed at 2
                0,  # device version major, TODO get from devie
                1,  # device version minor, TODO get from device
                1,  # device version build/point, TODO get from device
                CTAPHID_CAPABILITIES.CAPABILITY_CBOR
                | CTAPHID_CAPABILITIES.CAPABILITY_NMSG,  # these are the same for all BLE FIDO2 devices
            ),
            channel=channel,
        )
        pass

    async def send_hid_message(
        self, command: CTAPHID_CMD, payload: bytes, channel: int = None
    ):
        logging.debug(f"hid tx: command={command.name} payload={payload.hex()}")
        if channel is None:
            channel = self.channel
        offset_start = 0
        seq = 0
        while offset_start < len(payload):
            if seq == 0:
                capacity = self.hid_packet_size - 7
                response = struct.pack(">IBH", channel, 0x80 | command, len(payload))
            else:
                capacity = self.hid_packet_size - 5
                response = struct.pack(">IB", channel, seq - 1)
            response += payload[offset_start : (offset_start + capacity)]

            response += b"\0" * (self.hid_packet_size - len(response))

            self.device.send_input(response)

            offset_start += capacity
            seq += 1

    def handle_hid_message(self, channel, payload_without_channel):
        (cmd_or_seq,) = struct.unpack(">B", payload_without_channel[0:1])
        continuation = cmd_or_seq & 0x80 == 0
        cmd_or_seq = cmd_or_seq & 0x7F

        if not continuation:
            self.hid_command = CTAPHID_CMD(cmd_or_seq)
            (self.hid_total_length,) = struct.unpack(">H", payload_without_channel[1:3])
            self.hid_seq = -1
            self.hid_buffer = payload_without_channel[3 : 3 + self.hid_total_length]
        else:
            if cmd_or_seq != self.hid_seq + 1:
                logging.error(
                    f"Sequence out of order, expected {self.hid_seq + 1} got {cmd_or_seq}, payload={payload_without_channel.hex()}"
                )
                # there be dragons: CTAP_STATUS.CTAP1_ERR_INVALID_SEQ
                return
            payload = payload_without_channel[1:]
            remaining = self.hid_total_length - len(self.hid_buffer)
            self.hid_buffer += payload[:remaining]
            self.hid_seq = cmd_or_seq
        if self.hid_total_length == len(self.hid_buffer):
            self.active_tasks.append(
                asyncio.create_task(
                    self.hid_finish_receiving(channel), name="hid_finish_receiving"
                )
            )

    async def hid_finish_receiving(self, channel):
        try:
            connected_ble_device: CTAPBLEDevice = self.ble_device.get_connected_ble()
            while connected_ble_device is None:
                logging.debug("Reconnect to device")
                try:
                    await self.ble_device.reconnect()
                except Exception as error:
                    logging.warning(f"Reconnect failed: {error}")

                await asyncio.sleep(1)  # Wait before retrying
                connected_ble_device = self.ble_device.get_connected_ble()
            self.setup_timeout()

            if self.hid_command == CTAPHID_CMD.CBOR:
                await connected_ble_device.send_ble_message(
                    CTAPBLE_CMD.MSG, self.hid_buffer
                )
            elif self.hid_command == CTAPHID_CMD.CANCEL:
                await connected_ble_device.send_ble_message(
                    CTAPBLE_CMD.CANCEL, self.hid_buffer
                )
                for task in self.active_tasks:
                    if not task.done():
                        task.cancel()
                self.active_tasks = []
            elif self.hid_command == CTAPHID_CMD.ERROR:
                # this should not happen, as the error is sent from the fido2 device via BLE, not from the relying party.
                await connected_ble_device.send_ble_message(
                    CTAPBLE_CMD.ERROR, self.hid_buffer
                )
            elif self.hid_command == CTAPHID_CMD.PING:
                await connected_ble_device.send_ble_message(
                    CTAPBLE_CMD.PING, self.hid_buffer
                )
            elif self.hid_command in (
                CTAPHID_CMD.INIT,
                CTAPHID_CMD.WINK,
                CTAPHID_CMD.MSG,
                CTAPHID_CMD.LOCK,
            ):
                # TODO
                pass
        except Exception as error:
            logging.warning(f"Error during hid_finish_receiving, error={error}")

    def handle_ble_message(self, payload):
        (cmd_or_seq,) = struct.unpack(">B", payload[0:1])
        continuation = cmd_or_seq & 0x80 == 0
        cmd_or_seq = cmd_or_seq  # no adding of & 0x7F, as the command definitions include 0x80 for some reason in BLE

        if not continuation:
            self.ble_command = CTAPBLE_CMD(cmd_or_seq)
            (self.ble_total_length,) = struct.unpack(">H", payload[1:3])
            self.ble_buffer = payload[3 : 3 + self.ble_total_length]
            self.ble_seq = -1
        else:
            payload = payload[1:]
            # if cmd_or_seq != self.ble_seq + 1:
            #     self.handle_cancel(channel)
            #     self.send_error(channel, CTAP_STATUS.CTAP1_ERR_INVALID_SEQ)
            #     return
            remaining = self.ble_total_length - len(self.ble_buffer)
            self.ble_buffer += payload[:remaining]
            self.ble_seq = cmd_or_seq
        if self.ble_total_length == len(self.ble_buffer):
            self.active_tasks.append(asyncio.create_task(self.ble_finish_receiving()))

    async def ble_finish_receiving(self):
        logging.debug(
            f"ble rx: command={self.ble_command.name} payload={self.ble_buffer.hex()} device={self.ble_device.device_id}"
        )
        self.ble_device.keep_alive()
        if self.ble_command == CTAPBLE_CMD.MSG:
            await self.send_hid_message(CTAPHID_CMD.CBOR, self.ble_buffer)
        elif self.ble_command == CTAPBLE_CMD.KEEPALIVE:
            await self.send_hid_message(CTAPHID_CMD.KEEPALIVE, self.ble_buffer)
        elif self.ble_command == CTAPBLE_CMD.ERROR:
            await self.send_hid_message(CTAPHID_CMD.ERROR, self.ble_buffer)
        elif self.ble_command == CTAPBLE_CMD.PING:
            await self.send_hid_message(CTAPHID_CMD.PING, self.ble_buffer)
        elif self.ble_command == CTAPBLE_CMD.CANCEL:
            # Unsure if this case can happen, the cancel command comes from the relying party, not from the FIDO device
            await self.send_hid_message(CTAPHID_CMD.CANCEL, self.ble_buffer)
        else:
            pass
        self.ble_command = CTAPBLE_CMD.CANCEL
        self.ble_total_length = 0
        self.ble_buffer = bytes()
        self.ble_seq = -1

    async def check_timeout(self):
        while self.ble_device.timeout > 0:
            self.ble_device.timeout -= 100
            await asyncio.sleep(0.1)

        await self.ble_device.disconnect()
        i = 0
        while i < len(self.active_tasks):
            task = self.active_tasks[i]
            logging.debug(f"Task {task} is {task.done()}")
            if (
                isinstance(task, asyncio.Task)
                and "hid_finish_receiving" in task.get_name()
                and not task.done()
            ):
                i += 1  # Only increment if we didn't remove an element
            else:
                try:
                    task.cancel()
                    self.active_tasks.pop(i)
                except Exception as error:
                    logging.warning(f"Error when cancelling task, error: {error} ")
        self.active_channel = 0

    def setup_timeout(self):
        # Only create a new task if the previous one is completed
        if not self.timeout_task or self.timeout_task.done():
            self.timeout_task = asyncio.create_task(self.check_timeout())
