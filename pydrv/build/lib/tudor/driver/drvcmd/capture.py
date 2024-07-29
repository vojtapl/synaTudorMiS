from .cmd import *
from .context import *

import tudor.sensor


@cmd("enroll")
class CmdEnroll(Command):
    """
    Captures images from the sensor and enrolls
    Usage: enroll
    """

    def run(self, ctx: CmdContext, args: list):
        if not ctx.sensor.initialized:
            raise Exception("Sensor isn't initialized!")

        # Wait for finger to be lifted
        print("Waiting for finger to be lifted...")
        ctx.sensor.event_handler.wait_for_event(
            [tudor.sensor.SensorEventType.EV_FINGER_UP]
        )

        ctx.sensor.frame_capturer.enroll()


@cmd("auth")
class CmdAuth(Command):
    """
    Captures a frame from the sensor and tries to auth
    Usage: auth
    """

    def run(self, ctx: CmdContext, args: list):
        if not ctx.sensor.initialized:
            raise Exception("Sensor isn't initialized!")

        # Wait for finger to be lifted
        print("Waiting for finger to be lifted...")
        ctx.sensor.event_handler.wait_for_event(
            [tudor.sensor.SensorEventType.EV_FINGER_UP]
        )

        ctx.sensor.frame_capturer.auth()
