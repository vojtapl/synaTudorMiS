from .cmd import *
from .context import *

import tudor.sensor

ID_ZERO = b'\x00'*16


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

        # Capture images
        print("Capturing...")
        ctx.sensor.frame_capturer.enroll()


@cmd("auth")
class CmdAuth(Command):
    """
    Captures images from the sensor and tries to auth
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

        # Capture images
        print("Capturing...")
        ctx.sensor.frame_capturer.auth()


@cmd("db2_info")
class CmdDB2Info(Command):
    """
    Usage: db2_info
    """

    def run(self, ctx: CmdContext, args: list):
        ctx.sensor.frame_capturer.db2_get_info(print=True)


@cmd("db2_get_object_list")
class CmdDB2GetObjectList(Command):
    """
    Usage: db2_get_object_list <type> [<object_id>]
    """

    def run(self, ctx: CmdContext, args: list):
        if len(args) <= 0:
            raise Exception("No type given")

        if len(args) <= 1:
            obj_id = ID_ZERO
            print(f"No object_id given, using {obj_id}")
        else:
            obj_id = eval(args[1])

        obj_type = int(args[0])
        ctx.sensor.frame_capturer.get_object_list(obj_type, obj_id)


@cmd("db2_get_object_info")
class CmdDB2GetObjectInfo(Command):
    """
    Usage: db2_get_object_info <type> <object_id>
    """

    def run(self, ctx: CmdContext, args: list):
        if len(args) <= 1:
            raise Exception("No type and object_id given")

        obj_type = int(args[0])
        # TODO: find a better way to  convert
        obj_id = eval(args[1])
        print(ctx.sensor.frame_capturer.get_object_info(obj_type, obj_id))


@cmd("db2_get_all_object_info")
class CmdDB2GetAllObjectInfo(Command):
    """
    Usage: db2_get_all_object_info <type> <object_id>
    """

    def run(self, ctx: CmdContext, args: list):
        if len(args) <= 0:
            raise Exception("No type")

        if len(args) <= 1:
            obj_id = ID_ZERO
        else:
            obj_id = eval(args[1])

        obj_type = int(args[0])
        ctx.sensor.frame_capturer.get_all_object_info(obj_type, obj_id)


@cmd("db2_get_object_data")
class CmdDB2GetObjectData(Command):
    """
    Usage: db2_get_object_data <type> <object_id>
    """

    def run(self, ctx: CmdContext, args: list):
        if len(args) <= 1:
            raise Exception("No type and object_id given")

        obj_type = int(args[0])
        # TODO: find a better way to  convert
        obj_id = eval(args[1])
        print(ctx.sensor.frame_capturer.get_object_data(obj_type, obj_id))


@cmd("hw_info_get")
class CmdHwInfoGet(Command):
    """
    Usage: hw_info_get <type>
    """

    def run(self, ctx: CmdContext, args: list):
        if len(args) <= 0:
            raise Exception("No type and object_id given")

        info_type = int(args[0])
        print(ctx.sensor.frame_capturer.hw_info_get(info_type))


@cmd("db2_get_all_object_data")
class CmdDB2GetAllObjectData(Command):
    """
    Usage: db2_get_all_object_data <type> <object_id>
    """

    def run(self, ctx: CmdContext, args: list):
        if len(args) <= 0:
            raise Exception("No type")

        if len(args) <= 1:
            obj_id = ID_ZERO
        else:
            obj_id = eval(args[1])

        obj_type = int(args[0])
        ctx.sensor.frame_capturer.get_all_object_data(obj_type, obj_id)


@cmd("delete_template")
class CmdDeleteEnrollment(Command):
    """
    Usage: delete_template <tuid>
    """

    def run(self, ctx: CmdContext, args: list):
        if len(args) <= 0:
            raise Exception("No tuid")

        tuid = eval(args[0])
        ctx.sensor.frame_capturer.delete_template(tuid)

@cmd("db2_delete_object")
class CmdDB2DeleteObject(Command):
    """
    Usage: db2_delete_object <obj_type> <tuid>
    """

    def run(self, ctx: CmdContext, args: list):
        if len(args) <= 1:
            raise Exception("No obj_type or obj_id")

        obj_type = int(args[0])
        obj_id = eval(args[1])
        ctx.sensor.frame_capturer.db2_delete_object(obj_type, obj_id)


@cmd("db2_cleanup")
class CmdCleanup(Command):
    """
    Usage: db2_cleanup
    """

    def run(self, ctx: CmdContext, args: list):
        ctx.sensor.frame_capturer.db2_cleanup()


@cmd("db2_format")
class CmdForamt(Command):
    """
    Usage: db2_format
    """

    def run(self, ctx: CmdContext, args: list):
        ctx.sensor.frame_capturer.db2_format()


@cmd("storage_format")
class CmdStorageFormat(Command):
    """
    Usage: storage_format
    """

    def run(self, ctx: CmdContext, args: list):
        ctx.sensor.frame_capturer.storage_part_format()


@cmd("get_cache")
class CmdGetCache(Command):
    """
    Usage: get_cache
    """

    def run(self, ctx: CmdContext, args: list):
        cache = ctx.sensor.frame_capturer.get_enrollment_cache()
        if len(cache) == 0:
            print("cache is empty")
        else:
            print("cache:")
            for tuid, user_id, sub_id in cache:
                print(f"\ttuid: {tuid}")
                print(f"\tuser_id: {user_id}")
                print(f"\tsub_id: {sub_id}")
                print()


@cmd("print_start_info")
class CmdPrintStartInfo(Command):
    """
    Usage: print_start_info
    """

    def run(self, ctx: CmdContext, args: list):
        ctx.sensor.frame_capturer.print_start_info()


@cmd("read_host_partition")
class CmdReadHostPartition(Command):
    """
    Usage: read_host_partition
    """

    def run(self, ctx: CmdContext, args: list):
        print(ctx.sensor.frame_capturer.host_partition_read())


@cmd("host_partition_decode")
class CmdHostPartitionDecode(Command):
    """
    Usage: host_partition_decode
    """

    def run(self, ctx: CmdContext, args: list):
        ctx.sensor.frame_capturer.host_partition_decode()


@cmd("storage_get_info")
class CmdStorageGetInfo(Command):
    """
    Usage: storage_get_info
    """

    def run(self, ctx: CmdContext, args: list):
        ctx.sensor.frame_capturer.storage_get_info()


@cmd("reset_sbl_mode")
class CmdResetSblMode(Command):
    """
    Usage: reset_sbl_mode <anything for mode 2>
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


@cmd("get_common_property")
class CmdGetCommonProptery(Command):
    """
    Usage: get_common_property
    """

    def run(self, ctx: CmdContext, args: list):
        common_prop = ctx.sensor.frame_capturer.get_common_property()
        print(f"common_property: {common_prop}")

@cmd("host_partition_write_pairing_data")
class CmdHostPartitionWritePairingData(Command):
    """
    Usage: host_partition_write_pairing_data
    """

    def run(self, ctx: CmdContext, args: list):
        if ctx.pairing_data is None:
            raise ValueError("No pairing data present!")

        ctx.sensor.frame_capturer.host_partition_write_pairing_data(ctx.pairing_data)



# @cmd("set_idle_timeout")
# class set_idle_timeout(Command):
#     """
#     Usage: set_idle_timeout <timeout_ms>
#     """
#
#     def run(self, ctx : CmdContext, args : list):
#         if len(args) <= 0: raise Exception("No type and object_id given")
#
#         timeout_ms = int(args[0])
#         ctx.sensor.frame_capturer.set_idle_timeout(timeout_ms)
