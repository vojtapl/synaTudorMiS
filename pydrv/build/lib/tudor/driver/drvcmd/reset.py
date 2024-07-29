from .cmd import *
from .context import *

import tudor.sensor


@cmd("reset")
class CmdReset(Command):
    """Resets the sensor"""

    def run(self, ctx: CmdContext, _):
        ctx.sensor.reset()


@cmd("reset_sbl_mode")
class CmdResetSblMode(Command):
    """
    Usage: reset_sbl_mode <anything for mode 2 else number>
    """

    def run(self, ctx: CmdContext, args: list):
        if len(args) <= 0:
            print("no mode selected, choosing default False")
            is_mode_2 = False
        else:
            is_mode_2 = True

        ctx.sensor.frame_capturer.reset_sbl_mode(is_mode_2)


@cmd("reset_with_param")
class CmdResetSblModeParam(Command):
    """
    Usage: reset_with_param <int larger than or equal to two>
    """

    def run(self, ctx: CmdContext, args: list):
        if len(args) <= 0:
            print("no param given, aborting")
        else:
            param = int(args[0])
            ctx.sensor.frame_capturer.reset_with_param(param)
