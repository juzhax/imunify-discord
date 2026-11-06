#!/usr/bin/python3 -I
"""Start one on-demand scan. Called under flock by the managed cron job."""
import subprocess
import sys
from pathlib import Path


def read_config(path):
    config = {}
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        key, sep, value = line.partition('=')
        if not sep or key not in {'SCAN_CRON', 'SCAN_PATH', 'SCAN_CPU', 'SCAN_IO'} or key in config:
            raise ValueError('Invalid or duplicate configuration key.')
        config[key] = value
    if set(config) != {'SCAN_CRON', 'SCAN_PATH', 'SCAN_CPU', 'SCAN_IO'}:
        raise ValueError('Configuration must define SCAN_CRON, SCAN_PATH, SCAN_CPU and SCAN_IO.')
    if config['SCAN_CPU'] not in '1234567' or len(config['SCAN_CPU']) != 1 or config['SCAN_IO'] not in '1234567' or len(config['SCAN_IO']) != 1:
        raise ValueError('SCAN_CPU and SCAN_IO must be integers from 1 through 7.')
    if not Path(config['SCAN_PATH']).is_absolute() or not Path(config['SCAN_PATH']).is_dir():
        raise ValueError('SCAN_PATH must be an existing absolute directory.')
    validate_cron(config['SCAN_CRON'])
    return config


def validate_cron(value):
    fields = value.split()
    if len(fields) != 5:
        raise ValueError('SCAN_CRON must have five numeric cron fields.')
    for field, lower, upper in zip(fields, (0, 0, 1, 1, 0), (59, 23, 31, 12, 7)):
        for term in field.split(','):
            base, slash, step = term.partition('/')
            if slash and (not step.isdigit() or not 1 <= int(step) <= upper + 1):
                raise ValueError('Invalid cron step.')
            if base == '*':
                continue
            bounds = base.split('-')
            if len(bounds) > 2 or any(not n.isdigit() or not lower <= int(n) <= upper for n in bounds):
                raise ValueError('Invalid cron range.')
            if len(bounds) == 2 and int(bounds[0]) > int(bounds[1]):
                raise ValueError('Reversed cron range.')


def run(config, agent):
    # start is asynchronous. flock serializes submissions only; ImunifyAV owns
    # the scan lifecycle and handles its queue/busy state.
    result = subprocess.run([agent, 'malware', 'on-demand', 'start',
                             '--path', config['SCAN_PATH'], '--no-follow-symlinks', '--intensity-cpu', config['SCAN_CPU'],
                             '--intensity-io', config['SCAN_IO']], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=120)
    if result.returncode:
        raise RuntimeError('ImunifyAV rejected the scan; check agent health or active scans.')


if __name__ == '__main__':
    try:
        run(read_config('/etc/imunify-discord/config.env'),
            Path('/etc/imunify-discord/agent').read_text().strip())
    except Exception:
        print('Error: scheduled scan submission failed; check configuration, agent health and active scans.', file=sys.stderr)
        sys.exit(1)
