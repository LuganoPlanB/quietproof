#!/usr/bin/env python3
"""Measure real PoKC/PoSC APIs serially with a disposable, unfunded test key."""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
import signing_reference as ref
import bitcoin_core_signing_regtest as core


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def utc():
    return datetime.now(timezone.utc).isoformat()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--driver', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--rounds', type=int, choices=range(1, 10), default=3)
    args = parser.parse_args()
    driver = args.driver.resolve()
    # A new result path protects previous observations, including failures.
    with args.output.open('x') as output:
        report = {'schema': 1, 'started_utc': utc(), 'status': 'running',
                  'source_commit': subprocess.check_output(
                      ['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                  'host': {'system': platform.platform(), 'machine': platform.machine(),
                           'logical_cpus': os.cpu_count()},
                  'driver_sha256': sha(driver), 'measurements': [],
                  'method': 'Separate fresh process per relation; serial rounds. First prove '
                            'includes lazy identity work; verify follows prove. Signing, fixture '
                            'generation and shape inspection excluded; no chain RPC/policy work.'}
        cpuinfo = Path('/proc/cpuinfo')
        if cpuinfo.exists():
            report['host']['cpu'] = next(line.split(':', 1)[1].strip()
                for line in cpuinfo.read_text().splitlines() if line.startswith('model name'))
        # Record all current application headers and the measurement sources.
        paths = [ROOT/'CMakeLists.txt', ROOT/'tests/quietproof/relation_benchmark.cc',
                 Path(__file__).resolve(), ROOT/'tests/signing_reference.py',
                 ROOT/'tests/bitcoin_core_signing_regtest.py', *sorted((ROOT/'include').rglob('*.h'))]
        report['source_sha256'] = {str(p.relative_to(ROOT)): sha(p) for p in paths}

        def save():
            output.seek(0); json.dump(report, output, indent=2); output.write('\n')
            output.truncate(); output.flush()

        save()
        try:
            profile = json.loads((ROOT/'spec/signature-profile-v1.json').read_text())
            request = copy.deepcopy(next(v['request'] for v in profile['vectors']
                                         if v['request']['signing_kind'] == 0))
            now = int(time.time())
            request['not_before'], request['expires_at'] = now - 60, now + 86400
            request['claims'] = [c for c in request['claims'] if c['script_kind'] == 0][:1]
            key = b'\x02' + ref.GENERATOR[0].to_bytes(32, 'big')
            request['claims'][0]['program'] = ref.hash160(key).hex()
            derived = ref.virtual_profile(request)
            # Test-only d=1, k=1. Never sign a real/funded request with this tool.
            r = ref.GENERATOR[0]
            s = (int.from_bytes(derived['z'], 'big') + r) % ref.ORDER
            s = min(s, ref.ORDER - s)
            signature = core.encode_signature(r, s)
            if not ref.integer_verify(derived['z'], signature, key):
                raise RuntimeError('disposable signature self-check failed')
            signed = ref.serialize(core.replace_unlock(derived['tx'], 0, signature, key))
            receipt = struct.pack('>4sBBH32sI', b'QPA1', 1, 1, 1, derived['d'], len(signed)) + signed
            report['signature_request_sha256'] = hashlib.sha256(derived['request']).hexdigest()
            report['request_expires_at'] = request['expires_at']
            with tempfile.TemporaryDirectory(prefix='quietproof-benchmark-') as work:
                fixture = Path(work)/'private-fixture.json'
                fd = os.open(fixture, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'w') as stream:
                    json.dump({'request': derived['request'].hex(), 'receipt': receipt.hex()}, stream)
                for mode in ('pokc', 'posc'):
                    process_started_utc = utc()
                    start = time.monotonic()
                    result = subprocess.run([str(driver), str(fixture), mode, str(args.rounds)],
                                            capture_output=True, text=True, timeout=7200)
                    # Driver diagnostics contain only phase/timing information.
                    print(result.stderr, end='', file=sys.stderr, flush=True)
                    record = {'relation': mode, 'started_process_utc': process_started_utc,
                              'elapsed_s': time.monotonic() - start, 'exit_code': result.returncode}
                    if result.returncode == 0:
                        record['result'] = json.loads(result.stdout)
                        if len(record['result']['rows']) != args.rounds or not all(
                                row['verified'] for row in record['result']['rows']):
                            raise RuntimeError('incomplete benchmark')
                    report['measurements'].append(record); save()
                    result.check_returncode()
            report['status'] = 'passed'
        except Exception:
            report['status'] = 'failed'
            raise
        finally:
            report['finished_utc'] = utc(); save()


if __name__ == '__main__':
    main()
