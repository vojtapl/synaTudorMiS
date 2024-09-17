from __future__ import annotations

import enum
import logging
import pathlib
import struct
import os
import cryptography.hazmat.primitives.serialization as ser
import cryptography.hazmat.primitives.asymmetric.ec as ecc
import cryptography.hazmat.primitives.hashes as hashes
import tudor
import tudor.tls
from .iota import *
from .pair import *
from .sensor import *
from .event import *
from .windows_pairing_data import WINBIO_SAMPLE_SID
from .bmkt import *

# per vfmUtilAuthImageQuality
IMAGE_QUALITY_THRESHOLD = 50

MIS_IMAGE_METRICS_IPL_FINGER_COVERAGE = 0x1
MIS_IMAGE_METRICS_IMG_QUALITY = 0x10000

VCSFW_STORAGE_TUDOR_PART_ID_SSFS = 1
VCSFW_STORAGE_TUDOR_PART_ID_HOST = 2

OBJ_TYPE_USERS = 1
OBJ_TYPE_TEMPLATES = 2
OBJ_TYPE_PAYLOADS = 3

CONT_TAG_PROPERTY_ID = 4
CONT_TAG_PROPERTY_DATA = 5

HOST_TAG_VERSION = 1
HOST_TAG_PAIRED_DATA = 2

PAIR_DATA_TAG_VERSION = 0
PAIR_DATA_TAG_HOST_CERT = 1
PAIR_DATA_TAG_PRIVATE_KEY = 2
PAIR_DATA_TAG_SENSOR_CERT = 3
PAIR_DATA_TAG_PUB_KEY_SEC_DATA = 4
PAIR_DATA_TAG_SSI_STORAGE_PSK_ID = 5

ENROLL_TAG_TUID = 0
ENROLL_TAG_USERID = 1
ENROLL_TAG_SUBID = 2

# hardcoded value used in sensorUpdatePairHostPartitionProgram
HOST_PARITION_VERSION_TAG_DATA = b"\x01\x00\x00\x00"
PAIR_DATA_VERSION_TAG_DATA = b"\x00\x00"

# SBL revocery patch hashes hardcoded in synaWudfBioUsb111.dll
SBL_RECOVERY_HASHES = [0xB63DEB5F, 0x8ABDEFD6, 0x15595CEA, 0x9ACC5A48, 0x59A1E20D]


EV_FINGER_DOWN = 1
EV_FINGER_UP = 2
EV_FRAME_READY = 24

STATUS_SMT_LIKE_PROCESSING = 0x6EA
STATUS_OBJ_DOES_NOT_EXIST = 0x683
STATUS_SUCCESS = [0, 0x412, 0x5CC]
STATUS_MATCH_FAILED = 0x509

AUTH_IMG_QUALITY_THRESHOLD = 50

ID_ZERO = b"\x00" * 16
ID_FF = b"\xff" * 16


def load_sensor_key(
    fw_major: int, fw_minor: int, key_flag: bool
) -> ecc.EllipticCurvePublicKey:
    # Create sensor key name
    key_name = "%d.%d%s" % (fw_major, fw_minor, "-kf" if key_flag else "")

    # Create path
    path = str(pathlib.Path(__file__).parent)
    path += "/sensor_keys/"
    path += "%s.tsk" % key_name

    # Load key from path
    if not os.path.isfile(path):
        raise Exception("No sensor key '%s' found" % key_name)

    with open(path, "rb") as f:
        key = f.read()

    # Parse x and y (ECC public key)
    key_x = int.from_bytes(key[0:0x44], "little")
    key_y = int.from_bytes(key[0x44:0x88], "little")

    logging.log(tudor.LOG_PROTO, "Loaded sensor key '%s'" % key_name)
    return ecc.EllipticCurvePublicNumbers(key_x, key_y, ecc.SECP256R1()).public_key()


class SensorProductId(enum.IntEnum):
    PROD_ID1 = ord("5")
    PROD_ID2 = ord("8")
    PROD_ID3 = ord(":")
    PROD_ID4 = ord("<")
    PROD_ID5 = ord("A")
    BOOTLOADER_A = ord("B")
    BOOTLOADER_B = ord("C")


class SensorProvisionState(enum.IntEnum):
    UNPROVISIONED_A = 0
    UNPROVISIONED_B = 1
    PROVISIONED = 3

    @staticmethod
    def is_provisioned(state):
        return not (
            state == SensorProvisionState.UNPROVISIONED_A
            or state == SensorProvisionState.UNPROVISIONED_B
        )


class Sensor:
    IDLE_TIMEOUT = 200

    def __init__(self, comm: tudor.CommunicationInterface):
        self.comm = comm
        self.bootloader = tudor.sensor.SensorBootloader(self)
        self.tls_session = None
        self.event_handler = None
        self.initialized = False
        self.host_partition = tudor.win.HashTagValContainer()

        # Initial reset of the sensor
        self.reset()

        # If we're in bootloader mode, exit it
        if self.in_bootloader_mode():
            logging.log(tudor.LOG_INFO, "Sensor is in bootloader mode, exiting it...")
            self.bootloader.exit_bootloader_mode()
            if self.in_bootloader_mode():
                logging.log(
                    tudor.LOG_WARN,
                    "Sensor doesn't have a valid firmware, need to update to a valid one first!",
                )

    def reset(self):
        # Uninitialize sensor
        if self.initialized:
            self.uninitialize()

        logging.log(tudor.LOG_DETAIL, "Resetting sensor...")

        # Reset the sensor
        self.comm.reset()

        # Get the sensor state
        state_data = self.comm.send_command(
            struct.pack("<B", tudor.Command.GET_VERSION), 0x26
        )
        (
            self.fw_build_num,
            self.fw_major,
            self.fw_minor,
            product_id,
            self.id,
            flags1,
            flags2,
            prov_state,
        ) = struct.unpack("<2xxxxxIBBxbxxxx6sbbxxxxxxxxxxxB", state_data)
        self.id += bytes(2)
        self.advanced_security = (flags1 & 1) != 0
        self.key_flag = (flags2 & 0x20) != 0

        self.product_id = SensorProductId(product_id)
        self.prov_state = SensorProvisionState(prov_state & 0xF)

        if not self.in_bootloader_mode():
            # Read config version & some other IOTAs
            self.cfg_ver = ConfigVersionIOTA.read_from_comm(self.comm)
            self.ipl_iota = IplIOTA.read_from_comm(self.comm)
            self.iota_2e = PackedIOTA.read_from_comm(self.comm, 0x2E)
            self.wbf_param_iota = WbfParamIOTA.read_from_comm(self.comm)

            # Load the sensor key
            self.pub_key = load_sensor_key(self.fw_major, self.fw_minor, self.key_flag)

    def initialize(self, pairing_data: SensorPairingData):
        assert not self.initialized

        # Reset the sensor
        self.reset()

        logging.log(tudor.LOG_INFO, "Initializing sensor...")

        # We mustn't be in bootloader mode
        assert not self.in_bootloader_mode()

        # Log sensor info
        logging.log(tudor.LOG_DETAIL, "Sensor info:")
        logging.log(tudor.LOG_DETAIL, "    ID: %s" % self.id.hex())
        logging.log(
            tudor.LOG_DETAIL,
            "    FW version: %d.%d.%d"
            % (self.fw_major, self.fw_minor, self.fw_build_num),
        )
        logging.log(
            tudor.LOG_DETAIL,
            "    advanced security: %s"
            % ("present" if self.advanced_security else "not present"),
        )
        logging.log(
            tudor.LOG_DETAIL,
            "    key flag: %s" % ("set" if self.key_flag else "not set"),
        )
        logging.log(tudor.LOG_DETAIL, "    product id: %s" % self.product_id)
        logging.log(tudor.LOG_DETAIL, "    provision state: %s" % self.prov_state)
        logging.log(
            tudor.LOG_DETAIL,
            "    config version: %d.%d.%d"
            % (self.cfg_ver.major, self.cfg_ver.minor, self.cfg_ver.revision),
        )
        logging.log(
            tudor.LOG_DETAIL, "    WBF parameter: 0x%x" % self.wbf_param_iota.param
        )

        # Read and log start info
        start_data = self.comm.send_command(
            struct.pack("<B", tudor.Command.GET_START_INFO), 0x44
        )
        start_type, reset_type, start_code, sanity_panic, sanity_code, reset_nvinfo = (
            struct.unpack("<2xBBIII52s", start_data)
        )
        logging.log(tudor.LOG_DETAIL, "Start data:")
        logging.log(tudor.LOG_DETAIL, "    start type: 0x%02x" % start_type)
        logging.log(tudor.LOG_DETAIL, "    reset type: 0x%02x" % reset_type)
        logging.log(tudor.LOG_DETAIL, "    start code: 0x%x" % start_code)
        logging.log(tudor.LOG_DETAIL, "    sanity panic: 0x%x" % sanity_panic)
        logging.log(tudor.LOG_DETAIL, "    sanity code: 0x%x" % sanity_code)
        for i in range(13):
            logging.log(
                tudor.LOG_DETAIL,
                "    reset nvinfo [%02d]: 0x%08x"
                % (i, struct.unpack("<I", reset_nvinfo[4 * i : 4 * i + 4])[0]),
            )

        if self.is_paired():
            if pairing_data is None:
                raise Exception("No pairing data given")

            # Verify sensor certificate
            self.pub_key.verify(
                pairing_data.sensor_cert.signature,
                pairing_data.sensor_cert.signbytes(),
                ecc.ECDSA(hashes.SHA256()),
            )

            # Establish session
            self.tls_session = tudor.tls.TlsSession(
                self.comm,
                tudor.tls.TlsEccRemoteKey(
                    pairing_data.priv_key,
                    pairing_data.host_cert,
                    pairing_data.sensor_cert,
                ),
            )
            self.tls_session.establish()
            self.comm.set_tls_session(self.tls_session)
        else:
            logging.log(
                tudor.LOG_INFO,
                "Sensor is unprovisioned, not establishing TLS session...",
            )

        # Get frame dimensions
        (dim_data,) = struct.unpack(
            "<14x18s2x",
            self.comm.send_command(
                struct.pack("<HxxxxxBB", tudor.Command.FRAME_STATE_GET, 2, 7), 0x22
            ),
        )

        # Create event handler
        self.event_handler = tudor.sensor.SensorEventHandler(self)

        logging.log(tudor.LOG_INFO, "Sucessfully initialized sensor")
        self.initialized = True

    def uninitialize(self):
        assert self.initialized
        logging.log(tudor.LOG_INFO, "Uninitializing sensor...")

        # TODO Stop frame capturer

        # Stop event handler
        if self.event_handler.event_mask != []:
            self.event_handler.set_event_mask([])
        self.event_handler = None

        # Close TLS session
        if self.tls_session != None:
            self.comm.set_tls_session(None)
            self.tls_session.close()
            self.tls_session = None

        self.initialized = False

    def in_bootloader_mode(self):
        return self.product_id in (
            SensorProductId.BOOTLOADER_A,
            SensorProductId.BOOTLOADER_B,
        )

    def is_paired(self):
        return SensorProvisionState.is_provisioned(self.prov_state)

    def pair(self) -> SensorPairingData:
        # Reset sensor
        self.reset()
        if self.prov_state != 3:
            raise Exception("Pairing not needed")
        assert self.advanced_security

        logging.log(tudor.LOG_INFO, "Pairing sensor...")

        # Create keypair
        priv_key = ecc.generate_private_key(ecc.SECP256R1())

        # Create certificate and send it to sensor
        host_cert = SensorCertificate.create_host_cert(priv_key.public_key())
        resp = self.comm.send_command(
            struct.pack("<B", tudor.Command.PAIR) + host_cert.tobytes(), 0x322
        )

        # Get new host certificate and device certificate
        host_cert, dev_cert = SensorCertificate.frombytes(
            resp[2:402]
        ), SensorCertificate.frombytes(resp[402:802])

        # Return paring data
        return SensorPairingData(priv_key, host_cert, dev_cert)

    def unpair(self, data: SensorPairingData):
        assert self.initialized
        assert self.is_paired()

        logging.log(tudor.LOG_INFO, "Unpairing sensor...")

        # Reset sensor
        # That's all the Windows driver does :/
        self.reset()

    def __enter__(self):
        return self

    def __exit__(self, t, v, tb):
        if self.in_bootloader_mode():
            self.bootloader.exit_bootloader_mode()
        if self.initialized:
            self.uninitialize()

    def print_db2_info(self):
        logging.log(tudor.LOG_DETAIL, "getting DB2 info")

        db2_info = self.comm.send_command(
            struct.pack("<BB", tudor.Command.DB2_GET_DB_INFO, 1), 0x40
        )
        (
            dummy,
            version_major,
            version_minor,
            pversion,
            uop_length,
            top_length,
            pop_length,
            tempalte_object_size,
            payload_object_slot_size,
            num_current_users,
            num_deleted_users,
            num_available_user_slots,
            num_current_templates,
            num_deleted_templates,
            num_available_template_slots,
            num_current_payloads,
            num_deleted_payloads,
            num_available_slots,
        ) = struct.unpack("<2xHHHLHHHHHHHHHHHHHH", db2_info)
        print(
            f"DB2 info:\n"
            f"\tdummy: {dummy}\n"
            f"\tversion major: {version_major}\n"
            f"\tversion minor: {version_minor}\n"
            f"\tpversion: {pversion}\n"
            f"\tUOP length: {uop_length}\n"
            f"\tTOP length: {top_length}\n"
            f"\tPOP length: {pop_length}\n"
            f"\ttempalte object size: {tempalte_object_size}\n"
            f"\tpayload object slot size: {payload_object_slot_size}\n"
            f"\tnum current users: {num_current_users}\n"
            f"\tnum deleted users: {num_deleted_users}\n"
            f"\tnum available user slots: {num_available_user_slots}\n"
            f"\tnum current templates: {num_current_templates}\n"
            f"\tnum deleted templates: {num_deleted_templates}\n"
            f"\tnum available template slots: {num_available_template_slots}\n"
            f"\tnum current payloads: {num_current_payloads}\n"
            f"\tnum deleted payloads: {num_deleted_payloads}\n"
            f"\tnum available slots: {num_available_slots}\n"
        )

    def get_version(self):
        logging.log(tudor.LOG_DETAIL, "getting info")

        db2_info = self.comm.send_command(
            struct.pack("<B", tudor.Command.GET_VERSION), 38
        )
        (
            fw_build_time,
            fw_build_num,
            fw_version_major,
            fw_version_minor,
            fw_version_target,
            productid,
            silicon_revision,
            formal_release,
            platform,
            patch,
            serial_number1,
            serial_number2,
            security,
            interface,
            device_type,
            provision_state,
        ) = struct.unpack("<2xIIBBBBBBBBIHBQIB", db2_info)
        print(
            f"Version info:\n"
            f"\tfw_build_time: {fw_build_time}\n"
            f"\tfw_build_num: {fw_build_num}\n"
            f"\tfw_version_major: {fw_version_major}\n"
            f"\tfw_version_minor: {fw_version_minor}\n"
            f"\tfw_version_target: {fw_version_target}\n"
            f"\tproductid: {productid}\n"
            f"\tsilicon_revision: {silicon_revision}\n"
            f"\tformal_release: {formal_release}\n"
            f"\tplatform: {platform}\n"
            f"\tpatch: {patch}\n"
            f"\tserial_number: {serial_number1}{serial_number2}\n"
            f"\tsecurity: {security}\n"
            f"\tinterface: {interface}\n"
            f"\tdevice_type: {device_type}\n"
            f"\tprovision_state: {provision_state}\n"
        )

    def auth(
        self, tuid_list: list[bytes] = [], user_id=WINBIO_SAMPLE_SID, sub_id=None
    ) -> bool:
        # TODO: fix WINBIO_SAMPLE_SID
        self.capture_image(capture_flags=7)
        _, image_quality = self.mis_get_auth_image_metrics(
            MIS_IMAGE_METRICS_IMG_QUALITY
        )
        if image_quality is None:
            logging.warning("received NULL image quality")
            return False

        if image_quality < AUTH_IMG_QUALITY_THRESHOLD:
            logging.warning(
                "verified finger image has quality '%d' is lower than threshold '%d', discarding"
                % (image_quality, AUTH_IMG_QUALITY_THRESHOLD)
            )
            return False

        # NOTE:
        # aux_match mentioned in original code but seems not implemented
        # if ((phSensor->chachedCnt == 0) || ((pMatchParam->matchingScore & 3) != 3)) { aux_match }
        match_tuid, match_user_id, match_sub_id = self.mis_identify_match(
            tuid_list, b""
        )
        if match_tuid is None or match_user_id is None or match_sub_id is None:
            return False

        # check for match restrictions if given
        if tuid_list is not None and match_tuid not in tuid_list:
            return False
        if user_id is not None and user_id != match_user_id:
            return False
        if sub_id is not None and sub_id != match_sub_id:
            return False

        logging.info("Matched:")
        logging.info(f"\ttemplate UID: {match_tuid.hex()}")
        logging.info(f"\tuser ID: {match_user_id.hex()}")
        logging.info(f"\tsub ID: {match_sub_id.hex()}")
        return True

    def enroll(self, user_id=WINBIO_SAMPLE_SID, sub_id=b"\xf7"):
        logging.log(
            tudor.LOG_PROTO,
            "Starting enroll process... (does not check for identical fingerprints)",
        )

        try:
            self.mis_enroll_start()

            status = 0
            progress = 0
            tuid = ID_ZERO
            while progress != 100:
                self.event_handler.wait_for_event([SensorEventType.EV_FINGER_UP])
                self.capture_image()
                progress, status, tuid = self.mis_enroll_add_image()

            if status != 0:
                return False

            if input("Do you want to commit this enrollment? [Y/N]").lower() == "y":
                print("adding enrollment")
                self.add_enrollment(user_id, sub_id, tuid)

        finally:
            self.mis_enroll_finish()

    def add_enrollment(self, user_id: bytes, sub_id: bytes, tuid: bytes):
        # based on stiTudorAddEnrollment

        # lengths from decompilation and windbg
        assert len(tuid) == 0x10
        assert len(user_id) == 0x4C  # aka EID
        assert len(sub_id) == 0x01

        to_serialize = {}
        if len(tuid) != 0:
            to_serialize[0] = tuid
        if len(user_id) != 0:
            to_serialize[1] = user_id
        if len(sub_id) != 0:
            to_serialize[2] = sub_id
        # is unused (verified in windbg)
        # if len(additional_template_data) != 0:
        #     to_serialize[3] = additional_template_data
        serialized_commit_data = tudor.win.WinTagValContainer(to_serialize).tobytes()

        print(
            f"serialized data has len: {len(serialized_commit_data)} which <= 48? {len(serialized_commit_data) <= 48}"
        )
        print(f"\t-> data: {serialized_commit_data}")
        self.mis_enroll_commit(serialized_commit_data)

    def capture_image(self, capture_flags=15):
        logging.log(tudor.LOG_COMM, "Capturing image")
        self.event_handler.set_event_mask([SensorEventType.EV_FRAME_READY])
        self.send_frame_acq(capture_flags)

        self.event_handler.set_event_mask(
            [SensorEventType.EV_FRAME_READY, SensorEventType.EV_FINGER_DOWN]
        )
        self.event_handler.wait_for_events_no_set(
            [SensorEventType.EV_FINGER_DOWN, SensorEventType.EV_FRAME_READY]
        )
        self.event_handler.set_event_mask([])

        self.send_frame_finish()

    def storage_part_format(self):
        # based on tudorHostPartitionFormat
        SEND_LEN = 2

        to_send = struct.pack(
            "<BB",
            tudor.Command.STORAGE_PART_FORMAT,
            VCSFW_STORAGE_TUDOR_PART_ID_SSFS,
        )
        assert len(to_send) == SEND_LEN
        self.comm.send_command(to_send, 2)

        to_send = struct.pack(
            "<BB",
            tudor.Command.STORAGE_PART_FORMAT,
            VCSFW_STORAGE_TUDOR_PART_ID_HOST,
        )
        assert len(to_send) == SEND_LEN
        self.comm.send_command(to_send, 2)

    def send_frame_acq(self, capture_flags=15, trigger_mode=1):
        # NOTE: matches sent by orig. program
        logging.log(tudor.LOG_COMM, "Sending frame acquire")
        RECEIVED_SIZE = 2
        # SEND_SIZE = 8 + 9
        NO_RETRIES = 3

        if capture_flags == 7:
            param_x = 4116
        elif capture_flags == 15:
            param_x = 12
        else:
            raise ValueError("unimplemented capture_flags")

        num_frames = 1
        possibly_trig_mode = 1  # or 0

        reply = None
        msg = struct.pack(
            "<BIIHxBBBBB",
            0x80,
            param_x,
            num_frames,
            1,
            8,
            1,
            possibly_trig_mode,
            1,
            0,
        )
        print(f"msg: {msg}")
        for _ in range(NO_RETRIES):
            resp = self.comm.send_command(
                msg,
                RECEIVED_SIZE,
                check_response=False,
            )
            reply = struct.unpack("<H", resp)

            if reply == STATUS_SMT_LIKE_PROCESSING:
                logging.log(
                    tudor.LOG_COMM, "<- received STATUS_SMT_LIKE_PROCESSING, retrying"
                )
                continue
            else:
                break

        return reply in STATUS_SUCCESS

    def send_frame_finish(self):
        logging.log(tudor.LOG_COMM, "Sending frame finish")
        resp = self.comm.send_command(struct.pack("<B", tudor.Command.FRAME_FINISH), 2)
        return resp in STATUS_SUCCESS

    def mis_enroll_start(self, nonce_buffer_size=0):
        # based on misEnrollStart
        # TODO: what is nonce buffer for?

        SEND_LEN = 13
        resp_len = 6 + nonce_buffer_size
        send_nonce_buffer = int(nonce_buffer_size != 0)

        logging.log(tudor.LOG_COMM, "Sending enroll start")
        msg = struct.pack("<BIII", 0x96, 1, send_nonce_buffer, nonce_buffer_size)
        resp = self.comm.send_command(msg, resp_len)
        (nonce_buffer_size,) = struct.unpack("<xxI", resp[:6])

        nonce_buffer = resp[6:]
        logging.info(
            tudor.LOG_INFO,
            f"<- received nonce buffer with size: {nonce_buffer_size}, data: {nonce_buffer}",
        )
        assert len(nonce_buffer) == nonce_buffer_size
        return nonce_buffer

    def mis_enroll_add_image(self):
        # based on mimic misEnrollAddImage
        logging.log(tudor.LOG_COMM, "-> sending enroll add image")
        resp = self.comm.send_command(struct.pack("<BI", 0x96, 2), 82)

        tuid = resp[2 : 2 + 16]
        assert len(tuid) == 16

        (enroll_stat_buffer_len,) = struct.unpack("<I", resp[18 : 18 + 4])
        enroll_stat_buffer = resp[22:]
        assert enroll_stat_buffer_len == 60
        assert len(enroll_stat_buffer) == 60

        (
            unknown_1_2,
            progress,
            unknown_2_4,
            unknown_3_4,
            unknown_4_4,
            unknown_5_4,
            quality,
            redundant,
            rejected,
            unknown_6_4,
            template_count,
            enroll_quality,
            unknown_7_2,
            unknown_8_4,
            status,
            unknown_9_4,
            has_fixed_pattern,
        ) = struct.unpack("<HH 4I 3I I IH H I I I I", enroll_stat_buffer)

        # NOTE: the unknown sizes are pure quesses
        logging.info(
            "Added enroll image with info:\n"
            f"\ttuid: {tuid}\n"
            f"\tunknown_1_2: {unknown_1_2}\n"
            f"\tprogress: {progress}\n"
            f"\tunknown_2_4: {unknown_2_4}\n"
            f"\tunknown_3_4: {unknown_3_4}\n"
            f"\tunknown_4_4: {unknown_4_4}\n"
            f"\tunknown_5_4: {unknown_5_4}\n"
            f"\tquality: {quality}\n"
            f"\tredundant: {redundant}\n"
            f"\trejected: {rejected}\n"
            f"\tunknown_6_4: {unknown_6_4}\n"
            f"\ttemplate_count: {template_count}\n"
            f"\tenroll_quality: {enroll_quality}\n"
            f"\tunknown_7_2: {unknown_7_2}\n"
            f"\tunknown_8_4: {unknown_8_4}\n"
            f"\tstatus: {status}\n"
            f"\tunknown_8_4: {unknown_9_4}\n"
            f"\thas_fixed_pattern: {has_fixed_pattern}\n"
        )

        if rejected != 0:
            if redundant != 0:
                logging.warning("Image rejected due to being redundant: %d" % redundant)
            elif has_fixed_pattern == 0:
                logging.warning(
                    "Image rejected due to fixed pattern error: %d" % has_fixed_pattern
                )
            else:
                logging.warning("Image rejected due to bad quality: %d" % quality)
        if progress == 100:
            if status == 0:
                logging.log(
                    tudor.LOG_INFO,
                    "Enrollment completed successfully with quality %d"
                    % enroll_quality,
                )
            else:
                logging.error("Enrollment failed with status: %d" % status)

        return progress, status, tuid

    def mis_enroll_commit(self, enroll_commit_data: bytes):
        # based on _tudorCmdMisEnrollCommit
        SEND_LEN = 12 + 1 + len(enroll_commit_data)
        RESP_LEN = 2

        msg = struct.pack("<BIII", 0x96, 3, 0, len(enroll_commit_data))
        assert len(msg) == 12 + 1
        msg += enroll_commit_data
        assert len(msg) == SEND_LEN
        print(msg)
        self.comm.send_command(msg, RESP_LEN)

    def mis_enroll_finish(self):
        # based on misEnrollFinish
        logging.log(tudor.LOG_COMM, "-> sending enroll finish / commit")
        self.comm.send_command(struct.pack("<BI", 0x96, 4), 2)

    def mis_identify_match(self, tuid_list: list[bytes], data_2: bytes):
        # based on misIdentifyMatchCmd
        # in it it is used without arguments -> yields any match
        # assert len(data_1) == 16 * cnt_in_data_1

        # only one type of data can be send in decompiled funciton
        assert len(tuid_list) == 0 or len(data_2) == 0

        SEND_LEN = 13 + len(data_2) + len(tuid_list) * 16
        RECV_LEN = 1602

        if len(tuid_list) == 0:
            msg = struct.pack("<BI4xI", 0x99, 1, len(data_2))
            assert len(msg) == 13
            msg += data_2
        else:
            msg = struct.pack("<BII4x", 0x99, 1, len(tuid_list) * 16)
            assert len(msg) == 13
            for tuid in tuid_list:
                msg += tuid

        print(f"sending msg with len: {len(msg)} and data: {msg.hex()}")
        assert len(msg) == SEND_LEN

        resp = self.comm.send_command(msg, RECV_LEN, check_response=False)

        (status,) = struct.unpack("<H", resp[:2])
        # match failed given on indentify, obj does not exists given on verify
        if status in (STATUS_MATCH_FAILED, STATUS_OBJ_DOES_NOT_EXIST):
            logging.info("No match.")
            return None, None, None
        if status not in STATUS_SUCCESS:
            logging.error("Command failed with status 0x%4x" % status)
            return None, None, None

        # aka qm_struct_size in original function
        (match_stats_len, y_len, z_len) = struct.unpack("<3I", resp[18:30])
        assert match_stats_len == 36
        match_stats = resp[30 : 30 + 36]

        (match_score,) = struct.unpack("<I", match_stats[0 : 0 + 4])
        if match_score == 0:
            logging.warning("Match score is 0.")
            return None, None, None

        tuid = resp[2 : 2 + 16]
        y_offset = 30 + match_stats_len
        recv_data_y = resp[y_offset : y_offset + y_len]
        z_offset = y_offset + y_len
        recv_data_z = resp[z_offset : z_offset + z_len]

        logging.debug("Match info:")
        logging.debug(f"\ttuid: {tuid}")
        logging.debug(f"\tmatch_stats: {match_stats}")
        logging.debug(f"\tmatch_score: {match_score}")
        logging.debug(f"\ty_data_len: {y_len}, {recv_data_y}")
        logging.debug(f"\tz_data_len: {z_len}, {recv_data_z}")

        if y_len != 0 or z_len == 0:
            # I did not see this situation so no idea how to parse
            raise NotImplementedError

        print(recv_data_y)
        to_deserialize = tudor.win.WinTagValContainer.frombytes(recv_data_z)
        match_tuid = to_deserialize[ENROLL_TAG_TUID]
        match_user_id = to_deserialize[ENROLL_TAG_USERID]
        match_sub_id = to_deserialize[ENROLL_TAG_SUBID]

        # in original funciton it is not deserialized, so just in case assert equality
        assert tuid == match_tuid

        # others seems to be unused in decompiled function
        return match_tuid, match_user_id, match_sub_id

    def mis_get_auth_image_metrics(self, image_metrics):
        logging.log(tudor.LOG_COMM, "-> sending mis get image metrics")

        received_size = 10
        if image_metrics == MIS_IMAGE_METRICS_IPL_FINGER_COVERAGE:
            received_size = 14
        elif image_metrics == MIS_IMAGE_METRICS_IMG_QUALITY:
            received_size = 70
        else:
            raise NotImplementedError

        resp = self.comm.send_command(
            struct.pack("<BI", 0x9D, image_metrics), received_size
        )

        if len(resp) < 3:
            logging.warning(
                "<- sensor responded that image_metrics='%x' are unsupported"
                % image_metrics
            )
            return (None, None)

        (
            received_image_metrics,
            received_data_length,
        ) = struct.unpack("<2xII", resp[:10])

        logging.log(
            tudor.LOG_INFO,
            f"Asked for image_metrics: {image_metrics} and got: {received_image_metrics}, data_length: {received_data_length}",
        )

        if received_data_length == 0:
            logging.log(
                tudor.LOG_WARN,
                "sensor responded that image metrics cannot be queried now",
            )
            return (None, None)
        assert image_metrics == received_image_metrics

        if received_image_metrics == 1:
            assert received_data_length == 4

            (ipl_coverage,) = struct.unpack("<10xI", resp)
            logging.log(
                tudor.LOG_INFO,
                f"received finger coverage of IPL is %d%%" % ipl_coverage,
            )
            return (received_image_metrics, ipl_coverage)

        if received_image_metrics == 0x10000:
            assert received_data_length == 8
            # NOTE: unknown_4 does not match the values of IPL coverage
            (image_quality, unknown_4) = struct.unpack("<10x2I", resp)
            logging.log(
                tudor.LOG_INFO,
                f"received image quality is %d%% of qmExtractStatistics_t, unknown_4=%d"
                % (image_quality, unknown_4),
            )

            if image_quality < IMAGE_QUALITY_THRESHOLD:
                logging.warning(
                    "received image quality '%d' is lower that threshold '%d'"
                    % (image_quality, IMAGE_QUALITY_THRESHOLD)
                )
            return (received_image_metrics, image_quality)

        logging.error(
            "received unknown image metrics '%x' with length '%d"
            % (received_image_metrics, received_data_length)
        )
        return (None, None)

    # FIXME: does not work possibly due to being only usable during init/startup
    # def set_idle_timeout(self, timeout_ms):
    #     # based on setIDLETimeout
    #     SEND_LEN = 3
    #     RECV_LEN = 2
    #
    #     timeout = int((timeout_ms*1000)//80)
    #     print(timeout)
    #     msg = struct.pack("<BH", tudor.Command.SET_IDLE_TIMEOUT, timeout)
    #     assert len(msg) == SEND_LEN
    #     resp = self.comm.send_command(msg, RECV_LEN)

    def hw_info_get(self, info_type: int) -> None:
        # based on get_fwHwModuleInfo and query_HW_SBL_info

        SEND_LEN = 5
        # other random numbers were invalid
        assert info_type in (0, 1)

        if info_type == 1:
            recv_len = 10
        elif info_type == 0:
            recv_len = 18
        else:
            raise ValueError

        msg = struct.pack("<BI", tudor.Command.GET_HW_INFO, info_type)
        assert len(msg) == SEND_LEN
        resp = self.comm.send_command(msg, recv_len)

        if info_type == 0:
            (
                fm,
                hw_ver_1,
                hw_ver_2,
                pkg_info_main_id,
                pkg_info_sub_id_1,
                pkg_info_sub_id_2,
                unknown,
            ) = struct.unpack("<2x2I3H2B", resp)

            logging.info(
                f"Hw info: (Due to no CONFIG_VERSION iota, read the HW module info from IOTA chain 0 and FIB as following)"
                f"\tFM: {fm}\n"
                f"\tHwVer1: {hw_ver_1}\n"
                f"\tHwVer2: {hw_ver_2}\n"
                f"\tPkgInfoMainId: {pkg_info_main_id}\n"
                f"\tPkgInfoSubId1: {pkg_info_sub_id_1}\n"
                f"\tPkgInfoSubId2: {pkg_info_sub_id_2}\n"
                f"\tUnknown: {unknown}"
            )

        elif info_type == 1:
            (
                sbl_hash,
                status,
            ) = struct.unpack("<2xIB", resp[:7])

            logging.info(
                "Hw info: (Query the HW SBL info as following)\n"
                f"\tHASH: {hex(sbl_hash)}\n"
                f"\t-> HASH in hardcoded recovery patches: {sbl_hash in SBL_RECOVERY_HASHES}\n"
                f"\tstatus: {status}\n"
            )

        else:
            raise NotImplementedError

    def db2_get_info(self, print=True) -> tuple[int, int, int]:
        logging.log(tudor.LOG_DETAIL, "getting DB2 info")

        db2_info = self.comm.send_command(
            struct.pack("<BB", tudor.Command.DB2_GET_DB_INFO, 1), 0x40
        )
        (
            dummy,
            version_major,
            version_minor,
            partition_version,
            uop_length,
            top_length,
            pop_length,
            template_object_size,
            payload_object_slot_size,
            num_current_users,
            num_deleted_users,
            num_available_user_slots,
            num_current_templates,
            num_deleted_templates,
            num_available_template_slots,
            num_current_payloads,
            num_deleted_payloads,
            num_available_payload_slots,
        ) = struct.unpack("<2xHHHLHHHHHHHHHHHHHH", db2_info)

        if print:
            logging.info(
                f"received DB2 info:\n"
                f"\tdummy: {dummy}\n"
                f"\tversion major: {version_major}\n"
                f"\tversion minor: {version_minor}\n"
                f"\tpartition version: {partition_version}\n"
                f"\tUOP length: {uop_length}\n"
                f"\tTOP length: {top_length}\n"
                f"\tPOP length: {pop_length}\n"
                f"\ttemplate object size: {template_object_size}\n"
                f"\tpayload object slot size: {payload_object_slot_size}\n"
                f"\tnum current users: {num_current_users}\n"
                f"\tnum deleted users: {num_deleted_users}\n"
                f"\tnum available user slots: {num_available_user_slots}\n"
                f"\tnum current templates: {num_current_templates}\n"
                f"\tnum deleted templates: {num_deleted_templates}\n"
                f"\tnum available template slots: {num_available_template_slots}\n"
                f"\tnum current payloads: {num_current_payloads}\n"
                f"\tnum deleted payloads: {num_deleted_payloads}\n"
                f"\tnum available slots: {num_available_payload_slots}\n"
            )

        return num_current_users, num_current_templates, num_current_payloads

    def get_object_list(self, obj_type: int, obj_id: bytes) -> list[bytes]:
        # based on tudorCmdGetObjectList
        SEND_LEN = 20 + 1

        assert obj_type in (OBJ_TYPE_USERS, OBJ_TYPE_TEMPLATES, OBJ_TYPE_PAYLOADS)

        num_current_users, num_current_templates, num_current_payloads = (
            self.db2_get_info()
        )
        if obj_type == OBJ_TYPE_USERS:
            recv_len = 4 + 16 * num_current_users
        elif obj_type == OBJ_TYPE_TEMPLATES:
            recv_len = 4 + 16 * num_current_templates
        elif obj_type == OBJ_TYPE_PAYLOADS:
            recv_len = 4 + 16 * num_current_payloads
        else:
            raise ValueError("got incorrect obj_type")

        msg = struct.pack("<BI", tudor.Command.DB2_GET_OBJ_LIST, obj_type)
        assert len(obj_id) == 16
        msg += obj_id
        assert len(msg) == SEND_LEN

        resp = self.comm.send_command(msg, recv_len)

        id_list = resp[2:]
        (num_elements,) = struct.unpack("<H", id_list[:2])
        logging.info(
            "received object list of obj_type %d with %d elements"
            % (obj_type, num_elements)
        )

        id_list_parsed = []
        for i in range(num_elements):
            start_offset = 2 + 16 * i
            id_data = id_list[start_offset : start_offset + 16]
            id_list_parsed.append(id_data)
            logging.info(f"\tat idx {i} is: {id_data}")
        return id_list_parsed

    def get_object_info(self, obj_type: int, obj_id: bytes) -> bytes:
        # based on tudorCmdGetObjectInfo
        SEND_LEN = 20 + 1
        RECV_LEN_1 = 12
        RECV_LEN_2_3 = 52

        assert obj_type in (OBJ_TYPE_USERS, OBJ_TYPE_TEMPLATES, OBJ_TYPE_PAYLOADS)

        recv_len = RECV_LEN_1 if obj_type == OBJ_TYPE_USERS else RECV_LEN_2_3

        msg = struct.pack("<BI", tudor.Command.DB2_GET_OBJ_INFO, obj_type)
        assert len(obj_id) == 16
        msg += obj_id
        assert len(msg) == SEND_LEN

        resp = self.comm.send_command(msg, recv_len)

        obj_info = resp[2:]

        if obj_type == 1:
            print(f"\t0-1: {obj_info[0:2]}")
            (smt1,) = struct.unpack("<I", obj_info[2 : 2 + 4])
            print(f"\t2-5: {smt1}")
            (smt2,) = struct.unpack("<B", obj_info[2:3])
            print(f"\t2: {smt2}")
            print(f"\t6-10: {obj_info[6:10]}")

        elif obj_type in (2, 3):
            (smt1,) = struct.unpack("<H", obj_info[2 : 2 + 2])
            print(f"\t0-1: {obj_info[0:2]}")
            print(f"\t2-17 likely tuid: {obj_info[2:18]}")
            print(f"\t18-33 smt. that matches user_id: {obj_info[18:18+16]}")
            print(f"\t34-49 - some user prop. id: {obj_info[34:]}")
            (obj_data_size,) = struct.unpack("<I", obj_info[46 : 46 + 4])
            print(f"\t46-49: size of object data: {obj_data_size}")

        return obj_info

    def get_object_data(self, obj_type: int, obj_id: bytes) -> bytes:
        # based on tudorCmdGetObjectData
        SEND_LEN = 20 + 1

        assert obj_type in (OBJ_TYPE_USERS, OBJ_TYPE_TEMPLATES, OBJ_TYPE_PAYLOADS)
        if obj_type != OBJ_TYPE_PAYLOADS:
            logging.warning(
                "get_object_data is only used with OBJ_TYPE_PAYLOADS and seems not to work with any other types"
            )

        if obj_type == OBJ_TYPE_USERS:
            recv_len = 8
        else:
            obj_info = self.get_object_info(obj_type, obj_id)
            (obj_size,) = struct.unpack("<I", obj_info[46 : 46 + 4])

            if obj_type == OBJ_TYPE_TEMPLATES:
                recv_len = 8 + obj_size
            elif obj_type == OBJ_TYPE_PAYLOADS:
                recv_len = 8 + obj_size
            else:
                raise ValueError("got incorrect object type")

        msg = struct.pack("<BI", tudor.Command.DB2_GET_OBJ_DATA, obj_type)
        assert len(obj_id) == 16
        msg += obj_id
        assert len(msg) == SEND_LEN

        resp = self.comm.send_command(msg, recv_len)
        print(resp)

        (obj_data_len,) = struct.unpack("<I", resp[4 : 4 + 4])
        obj_data = resp[8:]
        assert len(obj_data) == obj_data_len
        return obj_data

    # FIXME: untested
    def write_object(
        self, obj_type: int, obj: bytes, obj_id: bytes | None = None
    ) -> bytes:
        # based on tudorCmdWriteObject
        SEND_LEN = 36 + len(obj) + 1
        RECV_LEN = 20

        assert obj_type in (OBJ_TYPE_USERS, OBJ_TYPE_TEMPLATES, OBJ_TYPE_PAYLOADS)

        msg = struct.pack("<BBB", tudor.Command.DB2_GET_OBJ_DATA, obj_type, 1)

        if obj_type == OBJ_TYPE_USERS:
            assert len(obj) == 4
            msg += obj
            msg += b"\x00" * (36 - len(msg))

        else:
            assert obj_id is not None and len(obj_id) == 16
            msg += obj_id

            msg += b"\x00" * (29 - len(msg))
            assert len(msg) == 29
            msg += struct.pack("<I", len(obj))
            assert len(msg) == 33
            assert len(obj) == 16
            msg += obj

        msg += obj
        assert len(msg) == SEND_LEN

        resp = self.comm.send_command(msg, RECV_LEN)

        obj_id = resp[4:]
        return obj_id

    # FIXME: untested
    def db2_delete_object(self, obj_type, obj_id):
        # based on tudorCmdDeleteObject
        SEND_LEN = 20 + 1
        RECV_LEN = 4

        assert obj_type in (OBJ_TYPE_USERS, OBJ_TYPE_TEMPLATES, OBJ_TYPE_PAYLOADS)

        msg = struct.pack("<BI", tudor.Command.DB2_GET_OBJ_DATA, obj_type)
        msg += obj_id
        assert len(msg) == SEND_LEN
        print(msg)

        resp = self.comm.send_command(msg, RECV_LEN)
        num_deleted_objects = struct.unpack("<2xH", resp)
        logging.info("Number of deleted objects: %d", num_deleted_objects)

    def db2_cleanup(self):
        # based on tudorCmdCleanup
        SEND_LEN = 1 + 1
        RECV_LEN = 8

        # NOTE: 1 is a parameter in the original function, but it is called only with 1
        msg = struct.pack("<BB", tudor.Command.DB2_CLEANUP, 1)
        assert len(msg) == SEND_LEN

        resp = self.comm.send_command(msg, RECV_LEN)
        num_erased_slots, new_partition_version = struct.unpack("<2xHI", resp)
        logging.info(
            "DB2 cleanup info: num_erased_slots=%d, new_partition_version=%d"
            % (num_erased_slots, new_partition_version)
        )

    def db2_format(self):
        # based on tudorCmdFormat
        SEND_LEN = 12 + 1
        RECV_LEN = 8

        to_send = struct.pack("<BB11x", tudor.Command.DB2_FORMAT, 1)
        assert len(to_send) == SEND_LEN
        resp = self.comm.send_command(to_send, RECV_LEN)
        print(resp)

        (
            unknown,
            new_partition_version,
        ) = struct.unpack("<2xHI", resp)

        logging.log(
            tudor.LOG_INFO,
            "DB2 format success with unknown: %x and new_partition_version: %d"
            % (unknown, new_partition_version),
        )

    def get_all_object_info(self, obj_type: int, obj_id: bytes):
        assert obj_type in (OBJ_TYPE_USERS, OBJ_TYPE_TEMPLATES, OBJ_TYPE_PAYLOADS)

        obj_list = self.get_object_list(obj_type, obj_id)
        if len(obj_list) == 0:
            print("Object list is empty")
            return

        for i in range(len(obj_list)):
            info = self.get_object_info(obj_type, obj_list[i])
            print(f'-> id: {obj_list[i]}, info: " {info}')
        return

    def get_all_object_data(self, obj_type: int, obj_id: bytes):
        assert obj_type in (OBJ_TYPE_USERS, OBJ_TYPE_TEMPLATES, OBJ_TYPE_PAYLOADS)

        obj_list = self.get_object_list(obj_type, obj_id)
        if len(obj_list) == 0:
            print("Object list is empty")
            return

        for i in range(len(obj_list)):
            data = self.get_object_data(obj_type, obj_list[i])
            print(f'\t-> id: {obj_list[i]} data: " {data}')
        return

    # FIXME: seemed not to work or I did not find the right tuid / id
    def delete_enrollment(self, tuid):
        logging.warning("This does not seem to work yet")
        # based on stiTudorDeleteEnrollment
        # NOTE: likely will not delete all enrollments, just a single template
        obj_info = self.get_object_info(OBJ_TYPE_TEMPLATES, tuid)
        logging.info(f"deleting template with tuid: {tuid}")
        self.delete_object(OBJ_TYPE_TEMPLATES, tuid)
        user_id = obj_info[18 : 18 + 16]
        logging.info(f"deleting user with user_id: {user_id}")
        self.delete_object(OBJ_TYPE_USERS, user_id)

    def get_enrollment_cache(self) -> list:
        # based on _updateEnrollmentCache

        # per stiTudorOpen
        CHACHE_TUID = (
            b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        )

        cache = []

        tuid_list = self.get_object_list(OBJ_TYPE_TEMPLATES, CHACHE_TUID)
        if len(tuid_list) == 0:
            logging.warning("Received empty tuid list")
            return cache

        for tuid in tuid_list:
            payload_id_list = self.get_object_list(OBJ_TYPE_PAYLOADS, tuid)
            if len(payload_id_list) == 0:
                logging.info(f"No payload data for an enrollment with tuid: {tuid}")
                continue

            for payload_id in payload_id_list:
                obj_data = self.get_object_data(OBJ_TYPE_PAYLOADS, payload_id)
                logging.debug(
                    f"tuid: {tuid}, payload_id: {payload_id} has obj_data: {obj_data}"
                )
                if len(obj_data) == 0:
                    continue

                to_deserialize = tudor.win.WinTagValContainer.frombytes(obj_data)
                tuid = to_deserialize[ENROLL_TAG_TUID]
                user_id = to_deserialize[ENROLL_TAG_USERID]
                sub_id = to_deserialize[ENROLL_TAG_SUBID]
                cache.append((tuid, user_id, sub_id))

        return cache

    # FIXME: untested
    def get_common_property(self, in_prop_id: bytes = ID_ZERO) -> bytes | None:
        # based on stiTudorGetCommonProperty

        common_prop_user_obj_id = self.get_common_prop_user_obj_id(create=False)
        if common_prop_user_obj_id is None:
            logging.warning("common_prop_user_obj_id not found")
            return None
        logging.info(f"found common_prop_user_obj_id: {common_prop_user_obj_id}")
        property_id, property_data = self.find_common_property(
            common_prop_user_obj_id, in_prop_id
        )
        if property_id is None or property_data is None:
            logging.warning("common property_id or property_data not found")
            return None

        assert len(property_data) == 16
        return property_data

    # FIXME: untested
    def set_common_property(self, prop_id: bytes, prop_data: bytes):
        # based on stiTudorSetCommonProperty
        # FIXME: find the values used and set them as default

        common_prop_user_id = self.get_common_prop_user_obj_id(create=True)
        if common_prop_user_id is None:
            logging.error("common_prop_user_obj_id not created?")
            return None
        property_id, _ = self.find_common_property(common_prop_user_id, prop_id)
        if property_id is not None:
            logging.info("found common property_id, deleting it")
            self.delete_object(OBJ_TYPE_TEMPLATES, property_id)

        container_dict = {
            CONT_TAG_PROPERTY_ID: prop_id,
            CONT_TAG_PROPERTY_DATA: prop_data,
        }
        container = tudor.win.WinTagValContainer(container_dict).tobytes()

        self.write_object(OBJ_TYPE_PAYLOADS, container, common_prop_user_id)

    # FIXME: untested
    def delete_common_property(self, prop_id: bytes) -> None:
        # based on stiTudorDeleteCommonProperty
        common_prop_user_id = self.get_common_prop_user_obj_id(create=False)
        if common_prop_user_id is not None:
            prop_id, _ = self.find_common_property(common_prop_user_id, prop_id)
            if prop_id is not None:
                self.delete_object(OBJ_TYPE_PAYLOADS, prop_id)

    # FIXME: untested
    def get_common_prop_user_obj_id(
        self, common_prop_user_obj_id: bytes = ID_ZERO, create: bool = False
    ) -> bytes | None:
        # based on _GetCommonPropUsrObjId
        user_id_list = self.get_object_list(OBJ_TYPE_USERS, ID_ZERO)
        if len(user_id_list) == 0:
            logging.warning("get_common_prop_user_obj_id: empty user_id_list")

        for user_id in user_id_list:
            user_info = self.get_object_info(OBJ_TYPE_USERS, user_id)

            is_common_property_user_id = user_info[2] == 1
            if is_common_property_user_id:
                return user_id

        if create:
            logging.info("Common property user is not found, creating")
            common_prop_obj = struct.pack("<B3x", 1)
            assert len(common_prop_obj) == 4
            common_prop_user_obj_id = self.write_object(
                OBJ_TYPE_USERS, common_prop_obj, obj_id=None
            )
            return common_prop_user_obj_id
        return None

    # FIXME: untested
    def find_common_property(
        self, common_prop_user_obj_id: bytes, property_id_to_match: bytes | None = None
    ) -> tuple[bytes | None, bytes | None]:
        # based on _tudorFindCommonProperty
        payload_id_list = self.get_object_list(
            OBJ_TYPE_PAYLOADS, common_prop_user_obj_id
        )
        for payload_id in payload_id_list:
            payload_data = self.get_object_data(OBJ_TYPE_PAYLOADS, payload_id)
            print(f"payload data: {payload_data}")

            container = tudor.win.WinTagValContainer.frombytes(payload_data)
            if (
                CONT_TAG_PROPERTY_DATA in container
                and CONT_TAG_PROPERTY_ID in container
            ):
                property_data = container[CONT_TAG_PROPERTY_DATA]
                property_id = container[CONT_TAG_PROPERTY_ID]
                print(container.vals)
                if (
                    property_id_to_match is not None
                    and property_id == property_id_to_match
                ) or property_id_to_match is None:
                    return (payload_id, property_data)
        return None, None

    def host_partition_read(self) -> bytes:
        part_id = VCSFW_STORAGE_TUDOR_PART_ID_HOST
        offset = 0
        size = 0x1000
        data = self.storage_read(part_id, offset, size)
        logging.info("received host partition with size %d", len(data))
        return data

    def storage_read(self, part_id: int, offset: int, size: int) -> bytes:
        SEND_LEN = 13
        recv_len = 8 + size

        # changing does not seem to do anything
        PARAM_2 = 0

        msg = struct.pack(
            "<BBBHII",
            tudor.Command.STORAGE_PART_READ,
            part_id,
            PARAM_2,
            0xFFFF,
            offset,
            size,
        )
        print(len(msg))
        assert len(msg) == SEND_LEN

        resp = self.comm.send_command(msg, recv_len)
        (recv_data_size,) = struct.unpack("<I", resp[2 : 2 + 4])
        assert recv_data_size == size
        return resp[8:]

    def host_partition_write(self, data: bytes) -> None:
        part_id = VCSFW_STORAGE_TUDOR_PART_ID_HOST
        offset = 0
        self.storage_write(part_id, offset, len(data), data)

    def storage_write(self, part_id: int, offset: int, size: int, data: bytes) -> None:
        send_len = 13 + size
        RECV_LEN = 6

        PARAM_2 = 0

        msg = struct.pack(
            "<BBBHII",
            tudor.Command.STORAGE_PART_WRITE,
            part_id,
            PARAM_2,
            0xFFFF,
            offset,
            size,
        )
        msg += data
        print(len(msg))
        assert len(msg) == send_len

        resp = self.comm.send_command(msg, RECV_LEN)
        (num_bytes_written,) = struct.unpack("<I", resp[2 : 2 + 4])
        assert num_bytes_written == size

    def host_partition_decode(self):
        host_partition = self.host_partition_read()
        data = tudor.win.HashTagValContainer.frombytes(host_partition)
        logging.info(
            f"Decoded host partition with keys: {data.vals.keys()} and hashes that match: {data.check_hashes()}"
        )
        if 1 in data.vals.keys():
            print(f"host partition verision: {data.vals[1]}")
            print(f"host partition verision length: {len(data.vals[1])}")
        if 2 in data.vals.keys():

            print(
                "not printing host partition data because if they are from Windows they cannot be easily decoded"
            )
            print(f"host partition data length: {len(data.vals[2])}")

    def host_partition_write_pairing_data(self, pairing_data: SensorPairingData):
        serialized = self.host_partition_serialize(pairing_data)
        self.host_partition_write(serialized)

    def host_partition_read_pairing_data(self) -> SensorPairingData:
        serialized = self.host_partition_read()
        pairing_data = self.host_partition_deserialize(serialized)
        return pairing_data

    def storage_get_info(self):
        SEND_LEN = 1
        RECV_LEN = 208

        msg = struct.pack("<B", tudor.Command.STORAGE_INFO_GET)
        resp = self.comm.send_command(msg, RECV_LEN)

        (
            unknown_1,
            unknown_2,
            unknown_3,
            unknown_4,
            unknown_5,
            unknown_6,
            num_partitions,
        ) = struct.unpack("<7H", resp[2:16])
        print("storage info:")
        print(f"\tunknown_1: {unknown_1}")
        print(f"\tunknown_2: {unknown_2}")
        print(f"\tunknown_3: {unknown_3}")
        print(f"\tunknown_4: {unknown_4}")
        print(f"\tunknown_5: {unknown_5}")
        print(f"\tunknown_6: {unknown_6}")
        print(f"\tnum_partitions: {num_partitions}")
        print("\tpartitions info:")

        for i in range(num_partitions):
            offset = 16 + 12 * i
            (
                partition_id,
                unknwon_9,
                unknown_7,
                unknown_8,
                partition_size,
            ) = struct.unpack("<BBHII", resp[offset : 12 + offset])
            print(f"\t  at idx {i}:")
            print(f"\t\tid: {partition_id}")
            print(f"\t\tunknwon_9: {unknwon_9}")
            print(f"\t\tunknown_7: {hex(unknown_7)}")
            print(f"\t\tunknown_8: {hex(unknown_8)}")
            print(f"\t\tsize: {partition_size}")

    def print_start_info(self):
        start_data = self.comm.send_command(
            struct.pack("<B", tudor.Command.GET_START_INFO), 0x44
        )
        start_type, reset_type, start_code, sanity_panic, sanity_code, reset_nvinfo = (
            struct.unpack("<2xBBIII52s", start_data)
        )
        logging.log(tudor.LOG_DETAIL, "Start data:")
        logging.log(tudor.LOG_DETAIL, "\tstart type: 0x%02x" % start_type)
        logging.log(tudor.LOG_DETAIL, "\treset type: 0x%02x" % reset_type)
        logging.log(tudor.LOG_DETAIL, "\tstart code: 0x%x" % start_code)
        logging.log(tudor.LOG_DETAIL, "\tsanity panic: 0x%x" % sanity_panic)
        logging.log(tudor.LOG_DETAIL, "\tsanity code: 0x%x" % sanity_code)
        for i in range(13):
            logging.log(
                tudor.LOG_DETAIL,
                "    reset nvinfo [%02d]: 0x%08x"
                % (i, struct.unpack("<I", reset_nvinfo[4 * i : 4 * i + 4])[0]),
            )

    def create_version_tag(self):
        # based on sensorUpdatePairHostPartitionProgram
        if HOST_TAG_VERSION not in self.host_partition:
            self.host_partition[HOST_TAG_VERSION] = HOST_PARITION_VERSION_TAG_DATA

    def reset_sbl_mode(self, is_type_2: bool = False):
        # based on reset_SBL_mode, params in: reset_sensor_2 and reset_sensor
        SEND_LEN = 0x15
        RESP_LEN = 2

        param_1 = 0xFFFFFFFF
        param_2 = 0xFF7FFFFF
        param_3 = 0
        param_4 = 0x400000
        param_5 = 0

        if is_type_2:
            param_2 = 0xFFBFFFFF
            param_4 = 0x800000

        msg = struct.pack(
            "<B5I",
            tudor.Command.RESET_SBL_MODE,
            param_1,
            param_2,
            param_3,
            param_4,
            param_5,
        )
        assert len(msg) == SEND_LEN
        self.comm.send_command(msg, RESP_LEN)

    def reset_with_param(self, param: int):
        # based on sendCmdReset
        SEND_LEN = 3
        RESP_LEN = 2

        if param < 2:
            logging.warning(
                "Per original funciton inputted value is too low, changing to 2"
            )
            param = 2

        msg = struct.pack("<BH", tudor.Command.REST, param)
        assert len(msg) == SEND_LEN
        self.comm.send_command(msg, RESP_LEN)

    def host_partition_serialize(self, pairing_data: SensorPairingData) -> bytes:
        pairing_data_plain = self.wrap_pairing_data(pairing_data)

        # TODO: add de/encryption
        pairing_data_encrypted = pairing_data_plain

        to_serialize = {
            HOST_TAG_VERSION: HOST_PARITION_VERSION_TAG_DATA,
            HOST_TAG_PAIRED_DATA: pairing_data_encrypted,
        }
        container = tudor.win.HashTagValContainer(to_serialize)

        hashes_match = container.check_hashes()
        assert hashes_match

        serialized = container.tobytes()
        return serialized

    def host_partition_deserialize(self, to_deserialize: bytes) -> SensorPairingData:

        deserialized = tudor.win.HashTagValContainer().frombytes(to_deserialize)

        hashes_match = deserialized.check_hashes()
        assert hashes_match

        # host_version = deserialized[HOST_TAG_VERSION]
        encrypted_pairing_data = deserialized[HOST_TAG_PAIRED_DATA]

        # TODO: add en/decryption
        unencrypted_pairing_data = encrypted_pairing_data

        pairing_data = self.unwrap_pairing_data(unencrypted_pairing_data)
        return pairing_data

    def wrap_pairing_data(self, pairing_data: SensorPairingData):
        # NOTE: this may be improved greatly
        # currently just a proof of concept
        encoding = ser.Encoding.PEM
        format = ser.PrivateFormat.PKCS8
        # no need to encrypt, as the whole container should be de/encrypted at once
        encryption = ser.NoEncryption()
        private_key_bytes = pairing_data.priv_key.private_bytes(
            encoding, format, encryption
        )
        # public_key_bytes = pairing_data.sensor_cert.priv_key.public_key().public_bytes(encoding, format, encryption)

        to_serialize = {
            PAIR_DATA_TAG_VERSION: PAIR_DATA_VERSION_TAG_DATA,
            PAIR_DATA_TAG_HOST_CERT: pairing_data.host_cert.tobytes(),
            PAIR_DATA_TAG_PRIVATE_KEY: private_key_bytes,
            PAIR_DATA_TAG_SENSOR_CERT: pairing_data.sensor_cert.tobytes(),
            # TODO: in original they seem to store a bit more
            # PAIR_DATA_TAG_PUB_KEY_SEC_DATA :
            # unused
            # PAIR_DATA_TAG_SSI_STORAGE_PSK_ID : ,
        }
        return tudor.win.WinTagValContainer(to_serialize).tobytes()

    def unwrap_pairing_data(self, to_unwrap: bytes) -> SensorPairingData:
        deserialized = tudor.win.WinTagValContainer().frombytes(to_unwrap)

        version = deserialized[PAIR_DATA_TAG_VERSION]
        host_cert_bytes = deserialized[PAIR_DATA_TAG_HOST_CERT]
        private_key_bytes = deserialized[PAIR_DATA_TAG_PRIVATE_KEY]
        sensor_cert_bytes = deserialized[PAIR_DATA_TAG_SENSOR_CERT]
        # TODO: in original they seem to store a bit more
        # public_key = deserialized[PAIR_DATA_TAG_PUB_KEY_SEC_DATA]

        print(version)
        assert version == PAIR_DATA_VERSION_TAG_DATA

        host_cert = SensorCertificate.frombytes(host_cert_bytes)
        # no need to encrypt, as the whole container should be de/encrypted at once
        private_key = ser.load_pem_private_key(private_key_bytes, None)
        sensor_cert = SensorCertificate.frombytes(sensor_cert_bytes)

        return SensorPairingData(private_key, host_cert, sensor_cert)

    def bmkt_send_msg(self, msg_id, seq_num=0, payload=b""):
        # A testing funciton for sending bmkt messages.
        RESP_LEN = 0x30
        header_id = BMKT_MESSAGE_HEADER_ID
        payload_len = len(payload)

        msg = struct.pack(
            "<B4B",
            VCSFW_CMD_ACE,
            header_id,
            seq_num,
            msg_id,
            payload_len,
        )
        msg += payload
        resp = self.comm.send_command(msg, RESP_LEN)

        (
            status,
            header_id,
            seq_num_recv,
            msg_id_recv,
            payload_len_recv,
        ) = struct.unpack("<H4B", resp[:6])
        payload = resp[6:]

        print("received bmkt message:")
        print(f"\tstatus: {status}")
        print(f"\theader_id: {header_id}")
        print(f"\tseq_num_recv: {seq_num_recv}")
        print(f"\tmsg_id_recv: {msg_id_recv} aka {bmkt_resp_get_str(msg_id_recv)}")
        print(f"\tpayload_len: {payload_len_recv}")
        print(f"\tpayload: {payload}")
        return (seq_num_recv, payload)

    def bmkt_fps_init(self):
        seq_num_recv, payload = self.bmkt_send_msg(BMKT_CMD_FPS_INIT)
        if len(payload) != 0:
            print(f"Init ok - finger on sensor: {payload.hex()}")

    def bmkt_power_down_notify(self):
        self.bmkt_send_msg(BMKT_CMD_POWER_DOWN_NOTIFY)

    def bmkt_enroll_user(self):
        user_id = b"\01" * 32
        finger = bytes(1)
        payload = bytes(0) + finger + user_id

        seq_num_recv, payload = self.bmkt_send_msg(BMKT_CMD_ENROLL_USER, 0, payload)

    def bmkt_cancel(self):
        seq_num_recv, payload = self.bmkt_send_msg(BMKT_CMD_CANCEL_OP)

    def bmkt_continuous_image_capture(self):
        seq_num_recv, payload = self.bmkt_send_msg(BMKT_CMD_CONTINUOUS_IMAGE_CAPTURE)

    def bmkt_continuous_image_capture_stop(self):
        seq_num_recv, payload = self.bmkt_send_msg(
            BMKT_CMD_CONTINUOUS_IMAGE_CAPTURE_STOP
        )

    def bmkt_get_security_level(self):
        seq_num_recv, payload = self.bmkt_send_msg(BMKT_CMD_GET_SECURITY_LEVEL)

    def bmkt_id_user(self):
        seq_num_recv, payload = self.bmkt_send_msg(BMKT_CMD_ID_USER)

    def bmkt_get_template_records(self):
        seq_num_recv, payload = self.bmkt_send_msg(BMKT_CMD_GET_TEMPLATE_RECORDS)

    def bmkt_get_enrolled_fingers(self):
        seq_num_recv, payload = self.bmkt_send_msg(BMKT_CMD_GET_ENROLLED_FINGERS)

    def bmkt_get_database_capacity(self):
        seq_num_recv, payload = self.bmkt_send_msg(BMKT_CMD_GET_DATABASE_CAPACITY)

    def bmkt_repeat_last_response(self):
        seq_num_recv, payload = self.bmkt_send_msg(BMKT_CMD_REPEAT_LAST_RSP)

    def bmkt_get_version(self):
        seq_num_recv, payload = self.bmkt_send_msg(BMKT_CMD_GET_VERSION)

    def bmkt_sensor_status(self):
        seq_num_recv, payload = self.bmkt_send_msg(BMKT_CMD_SENSOR_STATUS)

    def bmkt_get_final_result(self):
        seq_num_recv, payload = self.bmkt_send_msg(BMKT_CMD_GET_FINAL_RESULT)

    def gpio_write(self, state: bool):
        # based on tudorGPIOWrite
        SEND_LEN = 37
        RESP_LEN = 2

        # others not known
        VCSFW_SUBCMD_EXTSIG_WRITE = 3

        pin_name = "SIG_AL0_PIN"
        state_offset_from_string_start = 24  # that would be 24+9=31 from start
        assert len(pin_name) < state_offset_from_string_start

        print(f"Setting state of pin {pin_name} to {state}")

        padding_size = state_offset_from_string_start - len(pin_name)
        msg = struct.pack(
            f"<B I xBxx {len(pin_name)}s {padding_size}x Bxxx",
            0xAB,
            VCSFW_SUBCMD_EXTSIG_WRITE,
            1,
            bytes(pin_name, "ascii"),
            state,
        )
        assert len(msg) == SEND_LEN
        resp = self.comm.send_command(msg, RESP_LEN)
