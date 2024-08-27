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

        ctx.sensor.enroll()


@cmd("verify")
class CmdVerify(Command):
    """
    Captures a frame from the sensor and tries to match to given tuid
    Usage: verify <tuid_list>
    """

    def run(self, ctx: CmdContext, args: list):
        if not ctx.sensor.initialized:
            raise Exception("Sensor isn't initialized!")

        if len(args) < 1:
            raise Exception("No tuid list given")

        tuid = eval(args[0])

        # Wait for finger to be lifted
        print("Waiting for finger to be lifted...")
        ctx.sensor.event_handler.wait_for_event(
            [tudor.sensor.SensorEventType.EV_FINGER_UP]
        )


        ctx.sensor.auth(tuid)

@cmd("identify")
class CmdIdentify(Command):
    """
    Captures a frame from the sensor and tries to identify match
    Usage: identify
    """

    def run(self, ctx: CmdContext, args: list):
        if not ctx.sensor.initialized:
            raise Exception("Sensor isn't initialized!")

        # Wait for finger to be lifted
        print("Waiting for finger to be lifted...")
        ctx.sensor.event_handler.wait_for_event(
            [tudor.sensor.SensorEventType.EV_FINGER_UP]
        )

        ctx.sensor.auth()
