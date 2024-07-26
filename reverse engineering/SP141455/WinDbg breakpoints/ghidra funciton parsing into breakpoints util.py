import json

in_filename = "./funcs.json"
out_filename = "./funcs_parsed"
fx_driver_entry_um_offset = 0x180024420

do_not_use = ['try_get_function', 'WBFUsbResetPipe', 'initialize_stdio_handles_nolock',
              'initialize_inherited_file_handles_nolock', '_free_base', '_calloc_base',
              '_ismbblead', '_LocaleUpdate', 'FxDriverEntryUm']

with open(in_filename, "r", encoding='utf-8') as input_file:
    data = json.load(input_file)

output_file = open(out_filename, "w", encoding='utf-8')

for func_dict in data:
    name = func_dict['name']
    entry= func_dict['entry']

    name = name.replace('"', '')

    if name.startswith('__'):
        # print(f'discarding: name "{name}", entry: {entry}')
        continue

    if '<' in name or '>' in name:
        # print(f'discarding: name "{name}", entry: {entry}')
        continue


    if name.startswith('assemble_'):
        continue

    if 'type' in name \
            or 'lock' in name\
            or 'filter' in name \
            or 'state_case' in name:
        continue


    if 'process' in name:
        # print(f'discarding: name "{name}", entry: {entry}')
        continue

    if 'scan' in name:
        # print(f'discarding: name "{name}", entry: {entry}')
        continue

    if 'FID' in name:
        # print(f'discarding: name "{name}", entry: {entry}')
        continue

    if '$' in name:
        continue

    if 'guard' in name:
        continue

    if name.startswith("str"):
        continue

    if name.startswith("write_"):
        continue

    if name in do_not_use:
        continue


    if name.startswith('FUN'):
        entry = "0x" + entry
        entry = int(entry, 16)
        offset = entry - fx_driver_entry_um_offset
        sign = '+' if offset > 0 else ''
        offset = hex(offset)

        breakpoint = f'bp synawudfbiousb111!FxDriverEntryUm{sign}{offset} ".echo {name};g"\n'
        print(breakpoint, end='')
        output_file.write(breakpoint)

output_file.close()
