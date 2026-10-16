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

@cmd("gpio_write_test")
class CmdGpioWrite(Command):
    """
    Tries to send request for state change to GPIO AL0 pin (will likely enable/disable power button)
    Usage: gpio_write_test <state: True/False>
    """

    def run(self, ctx: CmdContext, args: list):
        if len(args) <= 0:
            raise Exception("No state specified!")
        state = eval(args[0])

        ctx.sensor.gpio_write(state)



@cmd("led")
class CmdLed(Command):
    """
    Sends one of the built-in LED_EX2 events of the Windows driver (v123)
    right away, also on sensors that aren't known to have an LED
    Usage: led <event: 0-5 or idle/waiting_for_finger/enroll_accepted/
                enroll_rejected/match_success/match_failure>
    """

    def run(self, ctx: CmdContext, args: list):
        if len(args) != 1:
            raise Exception("No LED event specified!")
        arg = args[0].strip()
        event = (
            tudor.sensor.LedEvent(int(arg, 0))
            if arg[0].isdigit()
            else tudor.sensor.LedEvent[arg.upper()]
        )
        ctx.sensor.led.send(event)
        print(f"LED event {event.value} ({event.name}) sent.")
