import argparse

"""
Quick and dirty log parser
"""

FUNCTION_START_MARKER = " >>>>>>>>\n"
FUNCTION_END_MARKER = " <<<<<<<<\n"

SPACES_OFFSET_CNT = 4
SPACES_ALLIGNMENT_CHAR_CNT = 50

PRINT_FIRST_PART = False

NOT_IMPLEMENTED_STR = "not implemented"
INVALID_STR = "invalid"
TUDOR_IOCTL_OPCODES = {
    1: NOT_IMPLEMENTED_STR,
    2: NOT_IMPLEMENTED_STR,
    3: "send any command",
    4: "enter bootloader mode",
    5: "exit bootloader mode",
    6: "SSI_IOCTL_CODE_BL_PATCH_LOAD",
    7: "SSI_IOCTL_CODE_IOTA_READ",
    9: "pair",
    10: "unpair",
    0x14: "SSI_IOCTL_CODE_GET_PIPE_ TIMEOUT",
    0x15: "SSI_IOCTL_CODE_SET_PIPE_TIMEOUT",
    0x16: "get sensor is in bootloader mode",
    0x1D: "something intereseting to inspect more",
    0x22: "SSI_IOCTL_CODE_SET_GET_PIPETIME_OUT",
    0x23: "update paired data",
    0x24: "get opinfo",
    0x2B: "frame finish",
    0x65: "do something with image dimensions",
}


def get_spaces_indicies(s: str):
    result = []

    for i in range(len(s)):
        if s[i] == " ":
            result.append(i)
    return result


def get_func_name(line: str) -> str | None:
    func_name = None
    if line.endswith(FUNCTION_START_MARKER):
        func_name = line.split(": ")[-1].rstrip(FUNCTION_START_MARKER)
    elif line.endswith(FUNCTION_END_MARKER):
        func_name = line.split(": ")[-1].rstrip(FUNCTION_END_MARKER)
    return func_name


def get_func_sets(file) -> tuple[set, set]:
    # some funcitnos with missing end log so get the list of one who do with both
    func_with_start_log = set()
    func_with_end_log = set()

    for line in input_file:
        func_name = get_func_name(line)
        if func_name is not None:
            if (
                line.endswith(FUNCTION_START_MARKER)
                and func_name not in func_with_start_log
            ):
                func_with_start_log.add(func_name)
            elif (
                line.endswith(FUNCTION_END_MARKER)
                and func_name not in func_with_end_log
            ):
                func_with_end_log.add(func_name)
    input_file.seek(0)

    func_with_both_log = set()
    for func_name_start in func_with_start_log:
        if func_name_start in func_with_end_log:
            func_with_both_log.add(func_name_start)

    func_with_any_log = func_with_start_log | func_with_end_log
    return func_with_both_log, func_with_any_log


def parse_opcode(line: str) -> str:
    line_before_opcode, tmp = line.split("(")
    opcode, line_after_opcode = tmp.split(")")

    opcode_int = int(opcode)
    if opcode_int in TUDOR_IOCTL_OPCODES:
        opcode_msg = TUDOR_IOCTL_OPCODES[opcode_int]
    else:
        opcode_msg = INVALID_STR

    return f"{line_before_opcode}({opcode} -> {opcode_msg}){line_after_opcode}"


parser = argparse.ArgumentParser(
    prog="WinDbg log parser", description="parses WinDbg logs for better readablity"
)
parser.add_argument("input_file", type=argparse.FileType("r"))
parser.add_argument("output_file", type=argparse.FileType("w"))
args = parser.parse_args()

input_file = args.input_file
output_file = args.output_file

func_with_both_log, func_with_any_log = get_func_sets(input_file)

current_offset = 0
for line in input_file:
    if "[1]" in line:
        func_name = get_func_name(line)

        # decrease offset on function start log
        if func_name is not None and func_name in func_with_both_log:
            if line.endswith(FUNCTION_END_MARKER):
                current_offset -= 1

        # add enter after a function start with zero offset
        if current_offset == 0 and line.endswith(FUNCTION_START_MARKER):
            output_file.write("\n")

        # modify the line
        line = line.lstrip("\t").lstrip(" ")
        offset_start = get_spaces_indicies(line)[5]
        if "opCode" in line:
            line = parse_opcode(line)

        # +1 to remove the space
        info_on_right = line[offset_start + 1 :]

        offset_padding = " " * SPACES_OFFSET_CNT * current_offset
        allignment_padding = ""
        info_on_left = ""

        if PRINT_FIRST_PART:
            info_on_left = line[:offset_start]
            if len(info_on_left) < SPACES_ALLIGNMENT_CHAR_CNT:
                allignment_padding = " " * (
                    SPACES_ALLIGNMENT_CHAR_CNT - len(info_on_left)
                )

        modified_line = (
            info_on_left + allignment_padding + offset_padding + info_on_right
        )
        output_file.write(modified_line)

        # increase offset on function start log
        if func_name is not None and func_name in func_with_both_log:
            if line.endswith(FUNCTION_START_MARKER):
                current_offset += 1

        # add enter before a function start with zero offset
        if current_offset == 0 and line.endswith(FUNCTION_END_MARKER):
            output_file.write("\n")
    else:
        # remove function names if they are already logged
        if line.rstrip("\n") in func_with_any_log:
            continue

        # write the line without a func_name in a pretty format
        allignment_padding = ""
        if PRINT_FIRST_PART:
            allignment_padding = " " * (SPACES_ALLIGNMENT_CHAR_CNT + 1)
        offset_padding = " " * SPACES_OFFSET_CNT * current_offset
        modified_line = allignment_padding + offset_padding + line
        output_file.write(modified_line)

input_file.close()
output_file.close()
print("DONE")
