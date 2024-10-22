import argparse
import logging
import traceback
import usb.core
import usb.util
from tudor import *
from tudor.sensor import *
from . import drvcmd

if __name__ == "__main__":
    # Argument parsing
    parser = argparse.ArgumentParser(
        prog="python -m tudor.driver",
        description="A python driver for some Synaptics Fingerprint sensors",
    )
    parser.add_argument(
        "-v",
        action="count",
        default=0,
        help="Increases log verbosity",
        dest="verbosity",
    )
    parser.add_argument(
        "-q", action="count", default=0, help="Decrease log verbosity", dest="quietness"
    )
    parser.add_argument(
        "--pair-data",
        help="The pairing data file to use",
        dest="pairfile",
        required=False,
    )
    parser.add_argument(
        "--pair-sample",
        help="Load pairing data from Windows sample",
        action="store_true",
        dest="sample_pairfile",
        required=False,
    )
    parser.add_argument(
        "-i",
        "--init",
        help="Init automatically if pair-data argument present",
        dest="init",
        action="store_true",
        required=False,
    )
    comm_parsers = parser.add_subparsers(
        title="Communication interface",
        help="Which communication interface to use",
        dest="comm",
        required=True,
    )

    usb_parser = comm_parsers.add_parser("usb", description="USB")
    usb_parser.add_argument(
        "--vid", help="The VID to search for", type=lambda x: int(x, 0), default=0x06CB
    )
    usb_parser.add_argument(
        "--pid", help="The PID to search for", type=lambda x: int(x, 0), default=0x00FF
    )

    args = parser.parse_args()
    if args.init and (args.pairfile is None and not args.sample_pairfile):
        raise ValueError("unable to init without pairfile")

    # Configure logging
    log_level = LOG_INFO - args.verbosity + args.quietness
    logging.basicConfig(
        level=log_level,
        format="\033[1m\033[90m%(levelname) 7s  \033[0m\033[37m%(message)s\033[0m",
    )
    logging.addLevelName(tudor.LOG_COMM, "COMM")
    logging.addLevelName(tudor.LOG_PROTO, "PROTO")
    logging.addLevelName(tudor.LOG_TLS, "TLS")
    logging.addLevelName(tudor.LOG_DETAIL, "DETAIL")
    logging.addLevelName(tudor.LOG_INFO, "INFO")
    logging.addLevelName(tudor.LOG_WARN, "WARN")

    # Create the communication interface
    comm: CommunicationInterface = None
    if args.comm == "usb":
        dev = usb.core.find(idVendor=args.vid, idProduct=args.pid)
        if dev is None:
            raise Exception("No sensor found!")
        else:
            logging.log(
                LOG_INFO, "Found sensor on bus %d device %d" % (dev.bus, dev.address)
            )
        comm = USBCommunication(dev)

    if log_level <= LOG_COMM:
        comm = LogCommunicationProxy(comm)

    # Open the sensor
    with Sensor(comm) as sensor:
        # Main command loop
        cmd_ctx = drvcmd.CmdContext(sensor)

        # load pairfile if specified
        if args.sample_pairfile:
            drvcmd.Command.commands["load_sample_pdata"].run(cmd_ctx, [])
        elif args.pairfile is not None:
            drvcmd.Command.commands["load_pdata"].run(cmd_ctx, [args.pairfile])

        if args.init:
            drvcmd.Command.commands["init"].run(cmd_ctx, [])

        while not cmd_ctx.exit_loop:
            try:
                cstr = input("\033[1m\033[94mtudor>\033[0m ")

                # Parse command
                cargs = cstr.split(" ")
                cmd = cargs[0].lower().strip()
                cargs = cargs[1:]

                # Run command
                if not cmd in drvcmd.Command.commands:
                    print("Unknown command. Try 'help' for a list of all commands.")
                else:
                    try:
                        drvcmd.Command.commands[cmd].run(cmd_ctx, cargs)
                    except KeyboardInterrupt:
                        print("Commaind interrupted")
                    except Exception:
                        print(
                            "Error while executing command: %s" % traceback.format_exc()
                        )
            except EOFError:
                break
            except KeyboardInterrupt:
                break

    # Close communication interface
    comm.close()
