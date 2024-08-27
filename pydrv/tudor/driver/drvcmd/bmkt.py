from .cmd import *
from .context import *

import tudor.sensor

# NOTE: Here are commands testing whether bmkt works in TLS session.

@cmd("bmkt_fps_init")
class CmdBmktFpsInit(Command):
    """
    Tesing command for sending bmkt messages
    Usage: bmkt_fps_init
    """

    def run(self, ctx: CmdContext, args: list):
        ctx.sensor.bmkt_fps_init()

@cmd("bmkt_power_down_notify")
class CmdBmktPowerDownNotify(Command):
    """
    Tesing command for sending bmkt messages
    Usage: bmkt_power_down_notify
    """

    def run(self, ctx: CmdContext, args: list):
        ctx.sensor.bmkt_power_down_notify()

@cmd("bmkt_enroll_user")
class CmdBmktEnrollUser(Command):
    """
    Tesing command for sending bmkt messages
    Usage: bmkt_enroll_user
    """

    def run(self, ctx: CmdContext, args: list):
        ctx.sensor.bmkt_enroll_user()

@cmd("bmkt_cancel")
class CmdBmktEnrollUser(Command):
    """
    Tesing command for sending bmkt messages
    Usage: bmkt_cancel
    """

    def run(self, ctx: CmdContext, args: list):
        ctx.sensor.bmkt_cancel()

@cmd("bmkt_continuous_image_capture")
class Cmdbmkt_continuous_image_capture(Command):
    """
    Tesing command for sending bmkt messages
    Usage: bmkt_continuous_image_capture
    """

    def run(self, ctx: CmdContext, args: list):
        ctx.sensor.bmkt_continuous_image_capture()

@cmd("bmkt_continuous_image_capture_stop")
class CmdBmkt_continuous_image_capture_stop(Command):
    """
    Tesing command for sending bmkt messages
    Usage: bmkt_continuous_image_capture_stop
    """

    def run(self, ctx: CmdContext, args: list):
        ctx.sensor.bmkt_continuous_image_capture_stop()

@cmd("bmkt_cmd_get_security_level")
class CmdBMKT_CMD_GET_SECURITY_LEVEL(Command):
    """
    Tesing command for sending bmkt messages
    Usage: bmkt_get_security_level
    """

    def run(self, ctx: CmdContext, args: list):
        ctx.sensor.bmkt_get_security_level()

@cmd("bmkt_cmd_id_user")
class CmdBMKT_CMD_ID_USER(Command):
    """
    Tesing command for sending bmkt messages
    Usage: bmkt_id_user
    """

    def run(self, ctx: CmdContext, args: list):
        ctx.sensor.bmkt_id_user()

@cmd("bmkt_cmd_get_template_records")
class CmdBMKT_CMD_GET_TEMPLATE_RECORDS(Command):
    """
    Tesing command for sending bmkt messages
    Usage: bmkt_get_template_records
    """

    def run(self, ctx: CmdContext, args: list):
        ctx.sensor.bmkt_get_template_records()

@cmd("bmkt_cmd_get_enrolled_fingers")
class CmdBMKT_CMD_GET_ENROLLED_FINGERS(Command):
    """
    Tesing command for sending bmkt messages
    Usage: bmkt_get_enrolled_fingers
    """

    def run(self, ctx: CmdContext, args: list):
        ctx.sensor.bmkt_get_enrolled_fingers()

@cmd("bmkt_cmd_get_database_capacity")
class CmdBMKT_CMD_GET_DATABASE_CAPACITY(Command):
    """
    Tesing command for sending bmkt messages
    Usage: bmkt_get_database_capacity
    """

    def run(self, ctx: CmdContext, args: list):
        ctx.sensor.bmkt_get_database_capacity()

@cmd("bmkt_cmd_repeat_last_response")
class CmdBMKT_CMD_REPEAT_LAST_RSP(Command):
    """
    Tesing command for sending bmkt messages
    Usage: bmkt_repeat_last_response
    """

    def run(self, ctx: CmdContext, args: list):
        ctx.sensor.bmkt_repeat_last_response()

@cmd("bmkt_cmd_get_version")
class CmdBMKT_CMD_GET_VERSION(Command):
    """
    Tesing command for sending bmkt messages
    Usage: bmkt_get_version
    """

    def run(self, ctx: CmdContext, args: list):
        ctx.sensor.bmkt_get_version()

@cmd("bmkt_cmd_get_version")
class CmdBMKT_CMD_GET_VERSION(Command):
    """
    Tesing command for sending bmkt messages
    Usage: bmkt_get_version
    """

    def run(self, ctx: CmdContext, args: list):
        ctx.sensor.bmkt_get_version()

@cmd("bmkt_cmd_sensor_status")
class CmdBMKT_CMD_SENSOR_STATUS(Command):
    """
    Tesing command for sending bmkt messages
    Usage: bmkt_sensor_status
    """

    def run(self, ctx: CmdContext, args: list):
        ctx.sensor.bmkt_sensor_status()

@cmd("bmkt_cmd_get_final_result")
class CmdBMKT_CMD_GET_FINAL_RESULT(Command):
    """
    Tesing command for sending bmkt messages
    Usage: bmkt_get_final_result
    """

    def run(self, ctx: CmdContext, args: list):
        ctx.sensor.bmkt_get_final_result()

