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


@cmd("led_off")
class CmdLedOff(Command):
    """Disable all configured LED states using a zeroed LED_EX2 table."""

    def run(self, ctx: CmdContext, args: list):
        if args:
            raise Exception("Usage: led_off")
        ctx.sensor.led_configure_raw(bytes(124))
        print("LED configuration cleared.")


# The six stock LED event records embedded in Kensington/Synaptics driver
# 6.0.20.1123.  Keeping only the small protocol constants here avoids loading
# or executing the proprietary Windows binary at runtime.
WINDOWS_LED_PROFILES = tuple(
    bytes.fromhex(profile)
    for profile in (
        "00000000000000000000002000000000000000000000000000000000000000200000000000000000000000000000000000000020000000000000000000000000000000000000002000000000000000000000000000000000000000200000000000000000000000000000000000000020000000000000000000000000",
        "00710200ffff000005050020000000000505000000000000ffff000005050020000000000505000000000000ffff000005050020000000000505000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "f4010000f4010000070500200000000005050000000000000000000000000020000000000000000000000000f401000000050020000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "e8030000f4010000070100200101000000000000000000000000000000000020000000000000000000000000f401000000010020000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "f4010000f4010000070500200000000005050000000000000000000000000020000000000000000000000000f401000000050020000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "e80300004b000000070100200101000000000000000000004b000000010000200000000000000000000000004b000000010100200000000000000000000000004b0000000100002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    )
)


@cmd("led_on")
class CmdLedOn(Command):
    """Light the reader steadily using stock Windows LED profile 1.

    The first two little-endian 32-bit words of a profile are durations.
    Profile 4 carries 500/500 and only flashes the LED for half a second,
    which is easy to mistake for working. Profile 1 carries 160000/65535
    and keeps the LED lit.
    """

    def run(self, ctx: CmdContext, args: list):
        if args:
            raise Exception("Usage: led_on")
        ctx.sensor.led_configure_raw(WINDOWS_LED_PROFILES[1])
        print("LED on (stock Windows profile 1).")


@cmd("led_windows_profile")
class CmdLedWindowsProfile(Command):
    """Apply one exact stock LED event profile (0..5) from driver 1123."""

    def run(self, ctx: CmdContext, args: list):
        if len(args) != 1:
            raise Exception("Usage: led_windows_profile <0..5>")
        profile = int(args[0], 10)
        if not 0 <= profile < len(WINDOWS_LED_PROFILES):
            raise ValueError("LED profile must be in range 0..5")

        config = WINDOWS_LED_PROFILES[profile]
        assert len(config) == 124
        ctx.sensor.led_configure_raw(config)
        print(f"Stock Windows LED profile {profile} accepted.")
