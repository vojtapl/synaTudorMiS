from .cmd import *
from .context import *

import tudor.sensor

ID_ZERO = b"\x00" * 16


# DB2 -------------------------------------------------------------------------


@cmd("db2_info")
class CmdDB2Info(Command):
    """
    Prints info about the DB2 database
    Usage: db2_info
    """

    def run(self, ctx: CmdContext, args: list):
        ctx.sensor.db2_get_info(print=True)


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
        ctx.sensor.get_object_list(obj_type, obj_id)


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
        print(ctx.sensor.get_object_info(obj_type, obj_id))


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
        ctx.sensor.get_all_object_info(obj_type, obj_id)


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
        print(ctx.sensor.get_object_data(obj_type, obj_id))


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
        ctx.sensor.get_all_object_data(obj_type, obj_id)


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
        ctx.sensor.db2_delete_object(obj_type, obj_id)


@cmd("db2_cleanup")
class CmdCleanup(Command):
    """
    Usage: db2_cleanup
    """

    def run(self, ctx: CmdContext, args: list):
        ctx.sensor.db2_cleanup()


@cmd("db2_format")
class CmdForamt(Command):
    """
    Usage: db2_format
    """

    def run(self, ctx: CmdContext, args: list):
        ctx.sensor.db2_format()


@cmd("delete_enrollment")
class CmdDeleteEnrollment(Command):
    """
    Usage: delete_enrollment <tuid>
    """

    def run(self, ctx: CmdContext, args: list):
        if len(args) <= 0:
            raise Exception("No tuid")

        tuid = eval(args[0])
        ctx.sensor.delete_enrollment(tuid)


@cmd("get_cache")
class CmdGetCache(Command):
    """
    Prints a cache of enrollments - tuid, user_id and sub_id for each enrollment
    Usage: get_cache
    """

    def run(self, ctx: CmdContext, args: list):
        cache = ctx.sensor.get_enrollment_cache()
        if len(cache) == 0:
            print("cache is empty")
        else:
            print("cache:")
            for tuid, user_id, sub_id in cache:
                print(f"\ttuid: {tuid}")
                print(f"\tuser_id: {user_id}")
                print(f"\tsub_id: {sub_id}")
                print()


@cmd("get_common_property")
class CmdGetCommonProptery(Command):
    """
    Usage: get_common_property
    """

    def run(self, ctx: CmdContext, args: list):
        common_prop = ctx.sensor.get_common_property()
        print(f"common_property: {common_prop}")


# Storage ---------------------------------------------------------------------


@cmd("storage_format")
class CmdStorageFormat(Command):
    """
    Usage: storage_format
    """

    def run(self, ctx: CmdContext, args: list):
        ctx.sensor.storage_part_format()


@cmd("storage_get_info")
class CmdStorageGetInfo(Command):
    """
    Usage: storage_get_info
    """

    def run(self, ctx: CmdContext, args: list):
        ctx.sensor.storage_get_info()


# Host partition --------------------------------------------------------------


@cmd("read_host_partition")
class CmdReadHostPartition(Command):
    """
    Usage: read_host_partition
    """

    def run(self, ctx: CmdContext, args: list):
        print(ctx.sensor.host_partition_read())


@cmd("host_partition_decode")
class CmdHostPartitionDecode(Command):
    """
    Try to decode host partition even if it is encrypted from Windows.
    Usage: host_partition_decode
    """

    def run(self, ctx: CmdContext, args: list):
        ctx.sensor.host_partition_decode()


@cmd("host_partition_write_pairing_data")
class CmdHostPartitionWritePairingData(Command):
    """
    Usage: host_partition_write_pairing_data
    """

    def run(self, ctx: CmdContext, args: list):
        if ctx.pairing_data is None:
            raise ValueError("No pairing data present!")

        ctx.sensor.host_partition_write_pairing_data(ctx.pairing_data)


@cmd("host_partition_read_pairing_data")
class CmdHostPartitionReadPairingData(Command):
    """
    Usage: host_partition_read_pairing_data
    """

    def run(self, ctx: CmdContext, args: list):
        if ctx.pairing_data is not None:
            resp = input("Do you want to override existing pairing data (y/n): ")
            resp = resp.strip().lower()
            if resp != "y":
                return

        ctx.pairing_data = ctx.sensor.host_partition_read_pairing_data()

        if ctx.pairing_data is not None:
            print("Host partition data read successfully")
        else:
            print("Error occured somewhere")
