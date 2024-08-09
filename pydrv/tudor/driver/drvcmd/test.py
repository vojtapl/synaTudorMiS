from .cmd import *
from .context import *

import tudor.sensor

@cmd("test")
class CmdTest(Command):
    """
    Usage: test
    """

    def run(self, ctx: CmdContext, args: list):
        ctx.sensor.test()
