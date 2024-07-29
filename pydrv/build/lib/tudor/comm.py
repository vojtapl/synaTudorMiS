from __future__ import annotations

import struct
import array
import time
import logging
import threading
import usb.core
import usb.util
import tudor.tls
from .log import *

SUCCESS_STATUS = [0, 0x412, 0x5CC]
SMT_LIKE_PROCESSING = 0x6EA


class Command:
    GET_VERSION = 0x1
    REST = 0x5
    PEEK = 0x7
    POKE = 0x8
    PROVISION = 0xE
    RESET_OWNERSHIP = 0x10
    GET_START_INFO = 0x19
    LED_EX2 = 0x39
    STORAGE_INFO_GET = 0x3E
    STORAGE_PART_FORMAT = 0x3F
    STORAGE_PART_READ = 0x40
    STORAGE_PART_WRITE = 0x41
    TLS_DATA = 0x44
    DB_OBJECT_CREATE = 0x47
    TAKE_OWNERSHIP_EX2 = 0x4F
    GET_CERTIFICATE_EX = 0x50
    SET_IDLE_TIMEOUT = 0x57
    BOOTLOADER_PATCH = 0x7D
    FRAME_READ = 0x7F
    FRAME_ACQ = 0x80
    FRAME_FINISH = 0x81
    FRAME_STATE_GET = 0x82
    EVENT_CONFIG = 0x86
    EVENT_READ = 0x87
    FRAME_STREAM = 0x8B
    READ_IOTA = 0x8E
    PAIR = 0x93
    DB2_GET_DB_INFO = 0x9E
    DB2_GET_OBJ_LIST = 0x9F
    DB2_GET_OBJ_INFO = 0xA0
    DB2_GET_OBJ_DATA = 0xA1
    DB2_DELETE_OBJ = 0xA3
    DB2_CLEANUP = 0xA4
    DB2_WRITE_OBJ = 0xA2
    DB2_FORMAT = 0xA5
    # UNKNOWN = 0xa6
    RESET_SBL_MODE = 0xAA
    SSO = 0xAC
    GET_OPINFO = 0xAE
    GET_HW_INFO = 0xAF

    UNKNOWN_NAME = "unknown CMD"
    names = {
        0x01: "VSCFW_CMD_GET_VERSION",
        0x05: "VCSFW_CMD_RESET",
        0x07: "VCSFW_CMD_PEEK",
        0x08: "VCSFW_CMD_POKE",
        0x0E: "VCSFW_CMD_PROVISION",
        0x10: "VCSFW_CMD_RESET_OWNERSHIP",
        0x15: UNKNOWN_NAME,
        0x19: "VCSFW_CMD_GET_STARTINFO",
        0x39: "VCSFW_CMD_LED_EX2",
        0x3E: "VCSFW_CMD_STORAGE_INFO_GET",
        0x3F: "VCSFW_CMD_STORAGE_PART_FORMAT",
        0x40: "VCSFW_CMD_STORAGE_PART_READ",
        0x41: "VCSFW_CMD_STORAGE_PART_WRITE",
        0x44: "tls data",
        0x47: "VCSFW_CMD_DB_OBJECT_CREATE",
        0x4F: "VCSFW_CMD_TAKE_OWNERSHIP_EX2",
        0x50: "VCSFW_CMD_GET_CERTIFICATE_EX",
        0x57: "VCSFW_CMD_TIDLE_SET",
        0x69: "enter/exit BL mode",
        0x7D: "VCSFW_CMD_BOOTLDR_PATCH",
        0x7F: "VCSFW_CMD_FRAME_READ",
        0x80: "VCSFW_CMD_FRAME_ACQ",
        0x81: "VCSFW_CMD_FRAME_FINISH",
        0x82: "VCSFW_CMD_FRAME_STATE_GET",
        0x86: "VCSFW_CMD_EVENT_CONFIG",
        0x87: "VCSFW_CMD_EVENT_READ",
        0x8B: "VCSFW_CMD_FRAME_STREAM",
        0x8E: "VCSFW_CMD_IOTA_FIND",
        0x93: "pair",
        0x96: "enroll start / commit",
        0x99: "identify match",
        0x9D: "get image metrics",
        0x9E: "VCSFW_CMD_DB2_GET_DB_INFO",
        0x9F: "VCSFW_CMD_DB2_GET_OBJECT_LIST",
        0xA0: "VCSFW_CMD_DB2_GET_OBJECT_INFO",
        0xA1: "VCSFW_CMD_DB2_GET_OBJECT_DATA",
        0xA2: "VCSFW_CMD_DB2_WRITE_OBJECT",
        0xA3: "VCSFW_CMD_DB2_[DELETE_OBJECT or CLEANUP]",
        0xA5: "VCSFW_CMD_DB2_FORMAT",
        0xA6: UNKNOWN_NAME,
        0xAA: "reset SBL mode",
        0xAC: "VCSFW_CMD_SSO",
        0xAE: "VCSFW_CMD_OPINFO_GET",
        0xAF: "VCSFW_CMD_HW_INFO_GET",
        -1: UNKNOWN_NAME,
    }

    @staticmethod
    def print(command):
        name = Command.names[command] if command in Command.names else Command.names[-1]
        logging.log(LOG_INFO, "\033[0;34mCMD  -> 0x%x - %s\033[0m" % (command, name))


class Response:
    RESPONSE_OK = "VCS_RESULT_OK"
    RESPONSE_BAD_PARAM = "VCS_RESULT_GEN_BAD_PARAM"
    RESPONSE_UNKNOWN = ""
    names = {
        0x000: RESPONSE_OK,
        0x401: "VCS_RESULT_SENSOR_BAD_CMD",
        0x403: "VCS_RESULT_GEN_OBJECT_DOESNT_EXIST",
        0x404: "VCS_RESULT_GEN_OPERATION_DENIED",
        0x405: RESPONSE_BAD_PARAM,
        0x406: RESPONSE_BAD_PARAM,
        0x407: RESPONSE_BAD_PARAM,
        0x412: RESPONSE_OK,
        0x509: "VCS_RESULT_MATCHER_MATCH_FAILED",
        0x5B6: "VCS_RESULT_SENSOR_FRAME_NOT_READY",
        0x5CC: RESPONSE_OK,
        0x680: "VCS_RESULT_DB_FULL",
        0x683: "VCS_RESULT_GEN_OBJECT_DOESNT_EXIST",
        0x6EA: "something like processing",
        -1: "VCS_RESULT_SENSOR_MALFUNCTIONED",
    }

    @staticmethod
    def print(response):
        name = (
            Response.names[response]
            if response in Response.names
            else Response.names[-1]
        )
        logging.log(LOG_INFO, "\033[0;34mRESP <- 0x%x - %s\033[0m" % (response, name))


class CommandFailedException(Exception):
    def __init__(self, status: int):
        response_str = (
            Response.names[status] if status in Response.names else Response.names[-1]
        )
        super().__init__(f"Command failed: status 0x%04x aka {response_str}" % status)
        self.status = status


class CommunicationInterface:
    def close(self):
        raise NotImplementedError()

    def reset(self):
        raise NotImplementedError()

    def end_command(
        self,
        cmd: bytes,
        resp_size: int,
        timeout: int = 2000,
        raw: bool = False,
        check_response=True,
    ) -> bytes:
        raise NotImplementedError()

    def set_tls_session(self, session: tudor.tls.TlsSession):
        raise NotImplementedError()

    def remote_tls_status(self) -> bool:
        raise NotImplementedError()

    def write_dft(self, data: bytes):
        raise NotImplementedError()

    def get_event_data(self) -> bytes:
        raise NotImplementedError()


class USBCommunication(CommunicationInterface):
    def __init__(self, dev):
        self.dev = dev
        self.dev.set_configuration()

        # Detach kernel drivers
        for i in range(self.dev.get_active_configuration().bNumInterfaces):
            if dev.is_kernel_driver_active(i):
                dev.detach_kernel_driver(i)

        # Claim the interface
        usb.util.claim_interface(dev, 0)
        self.intf = self.dev.get_active_configuration()[(0, 0)]

        # Find endpoints
        self.cmd_ep = self.intf[0]
        self.resp_ep = self.intf[1]
        self.intr_ep = usb.util.find_descriptor(
            self.intf,
            custom_match=lambda e: usb.util.endpoint_type(e.bEndpointAddress)
            == usb.util.ENDPOINT_TYPE_INTR,
        )

        assert not self.cmd_ep is None
        assert not self.resp_ep is None
        assert not self.intr_ep is None

        # Init the TLS session
        self.tls_session = None

    def close(self):
        usb.util.release_interface(self.dev, 0)
        self.dev.reset()
        self.dev = None

    def reset(self):
        self.tls_session = None
        self.dev.reset()

    def send_command(
        self, cmd, resp_size, timeout=2000, raw=False, check_response=True
    ):
        # Wrap and send command
        Command.print(cmd[0])

        wcmd = self.tls_session.wrap(cmd) if self.tls_session is not None else cmd
        self.cmd_ep.write(wcmd, timeout)

        # Receive wrapped resonse
        if self.tls_session is not None:
            resp_size += 0x45
        buf = array.array("B", [0 for _ in range(resp_size)])
        wresp = bytes(buf[: self.resp_ep.read(buf, timeout)])

        # Unwrap and parse response
        resp = self.tls_session.unwrap(wresp) if self.tls_session is not None else wresp

        if not raw:
            if len(resp) < 2:
                raise Exception("Invalid response")
            reply = struct.unpack("<H", resp[:2])[0]
            Response.print(reply)
            if check_response and reply not in SUCCESS_STATUS:
                raise CommandFailedException(struct.unpack("<H", resp[:2])[0])

        return resp

    def set_tls_session(self, session: tudor.tls.TlsSession):
        self.tls_session = session

    def remote_tls_status(self) -> bool:
        return (
            struct.unpack("<Bx", self.dev.ctrl_transfer(0xC0, 0x14, 0, 0, 2, 2000))[0]
            != 0
        )

    def write_dft(self, data: bytes):
        self.dev.ctrl_transfer(0x40, 0x15, 0, 0, data, 2000)

    def get_event_data(self) -> bytes:
        buf = array.array("B", [0 for _ in range(8)])
        # For some reason, Ctrl+C doesn't work while waiting on an interrupt endpoint
        # So we repeatedly timeout so that KeyboardInterrupts are triggered
        while True:
            try:
                num_read = self.intr_ep.read(buf, 1000)
                break
            except usb.core.USBTimeoutError:
                pass
        return bytes(buf[:num_read])


class LogCommunicationProxy(CommunicationInterface):
    proxied: CommunicationInterface

    def __init__(self, proxied):
        self.proxied = proxied

    def close(self):
        logging.log(LOG_COMM, "---------------------- CLOSE ---------------------")
        self.proxied.close()

    def reset(self):
        logging.log(LOG_COMM, "---------------------- RESET ---------------------")
        self.proxied.reset()

    def send_command(self, cmd, resp_size, timeout=2000, raw=False):
        Command.print(cmd[0])
        if raw:
            logging.log(LOG_COMM, "-> RAW REQ     | 0x%s" % cmd.hex())
            resp = self.proxied.send_command(cmd, resp_size, timeout, raw)
            logging.log(LOG_COMM, "<- RAW RESP    | 0x%s" % resp.hex())
            return resp
        else:
            logging.log(
                LOG_COMM,
                "-> cmd 0x%02x      | %s"
                % (struct.unpack("<B", cmd[:1])[0], cmd.hex()),
            )
            resp = self.proxied.send_command(cmd, resp_size, timeout, raw)
            logging.log(
                LOG_COMM,
                "<- status 0x%04x | %s"
                % (struct.unpack("<H", resp[:2])[0], resp.hex()),
            )
            return resp

    def set_tls_session(self, session: tudor.tls.TlsSession):
        if session is not None:
            logging.log(LOG_COMM, "---------- TLS session start ----------")
        else:
            logging.log(LOG_COMM, "---------- TLS session end ----------")
        self.proxied.set_tls_session(session)

    def remote_tls_status(self):
        logging.log(LOG_COMM, "-> remote TLS session status?")
        status = self.proxied.remote_tls_status()
        logging.log(
            LOG_COMM,
            "<- remote TLS session status: %s"
            % ("established" if status else "not established"),
        )
        return status

    def write_dft(self, data: bytes):
        logging.log(LOG_COMM, "-> DFT write: %s" % data.hex())
        self.proxied.write_dft(data)

    def get_event_data(self) -> bytes:
        logging.log(LOG_COMM, "-> get event data")
        data = self.proxied.get_event_data()
        logging.log(LOG_COMM, "<- event data: %s" % data.hex())
        return data
