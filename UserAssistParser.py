from Registry import Registry
from pathlib import Path
import codecs
import argparse
import struct
from datetime import datetime, timedelta
import csv
import sys
from lib.known_folders import folder_guids

examples = '''
python UserAssistParser.py -f ntuser.dat -o \\path\\to\\out
'''


def convert_filetime(ft):
    """
    convert 64-bit FILETIME
    :param ft: FILETIME
    :return: UTC timestamp
    """
    EPOCH_AS_FILETIME = 116444736000000000
    HUNDREDS_OF_NANOSECONDS = 10000000
    return datetime.utcfromtimestamp((ft - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS).strftime(
        '%Y-%m-%d %H:%M:%S (UTC)')


def get_key(file):
    """
    yank programs and data from UA Count keys
    :param file: path to NTUSER.dat hive file
    :return: decoded programs and data dict
    """
    pd_list = []  # list to hold dicts of decoded programs/data
    try:
        reg_hive = Registry.Registry(str(file))
    except Registry.RegistryParse.ParseException:
        sys.exit(f'\n[x] Wrong file type, regf Signature not found')

    if reg_hive.hive_type().value == 'ntuser.dat':
        try:
            ua_key = reg_hive.open('SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist')
        except Registry.RegistryKeyNotFoundException:
            print(f'[x] UserAssist key not found')
        else:
            print(f'\n[+] Found {ua_key}')
            for guid in ua_key.subkeys():
                if guid.subkey('Count').values():
                    print(f'[+] Found GUID with values: {guid.name()}')
                    print('[+] Parsing values...')
                    for value in guid.subkey('Count').values():
                        pd_dict = {}  # dict to hold decoded programs and data
                        program = resolve_guid(codecs.encode(value.name(), 'rot-13'))
                        parsed_data = raw_data_parser(value.value())
                        # dict contains program name: run count, focus count, focus time, last executed
                        pd_dict[program] = parsed_data
                        pd_list.append(pd_dict)
        return pd_list
    else:
        print(f'\n{ntuser_path.name} is not an NTUSER.DAT file')


def raw_data_parser(data):
    """
    parse raw data for individual program in UA key
    :param data: binary data
    :return: list: run count, focus count, focus time, last executed time
    """
    ua_data = []

    if len(data) == 16:  # WinXP
        # little-endian DWORD
        run_count = struct.unpack("<I", data[4:8])[0]
        # run count starts at 5
        run_count -= 5
        focus_count = ''
        focus_time = ''
        # last executed in FILETIME. little-endian QWORD
        ft = struct.unpack("<Q", data[8:])[0]

        if not ft:
            last_executed = ''  # no last run recorded
        else:
            last_executed = convert_filetime(ft)
        ua_data.extend([run_count, focus_count, focus_time, last_executed])

    elif len(data) == 72:  # Win7+
        # little-endian DWORD
        run_count = struct.unpack("<I", data[4:8])[0]
        # little-endian DWORD
        focus_count = struct.unpack("<I", data[8:12])[0]
        # little-endian DWORD. focus time in milliseconds
        focus_time = str(timedelta(milliseconds=struct.unpack("<I", data[12:16])[0])).split('.')[0]
        # last executed in FILETIME. little-endian QWORD
        ft = struct.unpack("<Q", data[60:68])[0]

        if not ft:
            last_executed = ''  # no last run recorded
        else:
            last_executed = convert_filetime(ft)
        ua_data.extend([run_count, focus_count, focus_time, last_executed])

    return ua_data


def resolve_guid(program):
    """
    convert GUIDs to known folder
    :param program: program path
    :return: program path w/ resolved folders
    """
    for key, val in folder_guids.items():
        if key == program.split('\\')[0]:
            resolved = program.replace(key, val)
            return resolved
        else:
            continue
    return program


def write_output(ua_list, out_path):
    """
    Write CSV output
    :param ua_list: list of dicts containing decoded programs and parsed data
    :param out_path: output path to write CSV
    :return: nothing
    """
    out_dir = Path(out_path)
    if not out_dir.exists():
        out_dir.mkdir(parents=True, exist_ok=True)

    out_file = out_dir / 'UserAssist.csv'
    header = ['Program', 'Run Count', 'Focus Count', 'Focus Time', 'Last Executed']

    with out_file.open('w', newline='') as fh:
        write_csv = csv.writer(fh)
        write_csv.writerow(header)
        for program in ua_list:
            for key, val in program.items():
                if not val:
                    pass
                else:
                    row = [key, val[0], val[1], val[2], val[3]]
                    write_csv.writerow(row)
    print(f'[+] Output written to {out_file}')


def main():
    if ntuser_path.is_file():
        ua_dict = get_key(str(ntuser_path))
        write_output(ua_dict, args.out)
    else:
        print(f'\nInvalid file path: {ntuser_path}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='UserAssist Parser', epilog=examples,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-f', '--file', type=str, help='Path to ntuser.dat file')
    parser.add_argument('-o', '--out', type=str, help='Path to write output')
    args = parser.parse_args()
    ntuser_path = Path(args.file)
    main()
