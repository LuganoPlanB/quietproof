#!/usr/bin/env python3
"""Atomic final-clock boundaries, held locks, concurrent replay and restarts."""
import argparse
import fcntl
import os
from pathlib import Path
import select
import subprocess
import tempfile
import time

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--driver', type=Path, required=True)
    args = parser.parse_args()
    cases = 0
    owned = []
    held = []
    with tempfile.TemporaryDirectory(prefix='quietproof-final-acceptance-') as directory:
        root = Path(directory)
        clock = root/'now'
        clock.write_text('150')

        def result(process):
            output, error = process.communicate(timeout=5)
            assert process.returncode == 0 and not error
            assert b'private-clock-error' not in output+error
            words = output.splitlines()[-1].split()
            return words[0].decode(), int(words[1]), int(words[2])

        def spawn(path, mode='accept', nonce=1, gate=None):
            command = [args.driver, mode, path, clock, str(nonce)]
            if gate is not None:
                command.append(str(gate))
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
                                       pass_fds=() if gate is None else (gate,))
            owned.append(process)
            assert select.select([process.stdout], [], [], 5)[0], 'child did not reach start gate'
            assert process.stdout.readline() == b'ready\n'
            return process

        def run(path, expected, now='150', mode='accept', nonce=1):
            nonlocal cases
            clock.write_text(now)
            value = result(spawn(path, mode, nonce))
            assert value[0] == expected, (expected, value[0])
            cases += 1
            return value

        try:
            store = root/'boundaries'
            run(root/'zero-nonce', 'invalid_request', nonce=0)
            run(store, 'not_yet_valid', '99')
            assert store.read_bytes() == b''
            assert run(store, 'accepted', '100') == ('accepted', 100, 1)
            run(store, 'replay', '199')
            run(store, 'expired', '200', nonce=2)
            assert len(store.read_bytes()) == 65
            # A second process reopens the persisted store after the accepting
            # process has exited; no process-local cache supplies replay state.
            run(store, 'replay', '150')
            run(store, 'replay', '150', mode='legacy')
            legacy = root/'legacy-first'
            run(legacy, 'accepted', mode='legacy')
            run(legacy, 'replay')
            for failure in ('fail', 'throw'):
                path = root/failure
                run(path, 'clock_unavailable', failure)
                assert path.read_bytes() == b''
                run(path, 'accepted')
            unsafe = root/'unsafe'; unsafe.write_bytes(b'private-store-error-must-not-appear')
            unsafe.chmod(0o644)
            run(unsafe, 'store_failure')
            unsafe.chmod(0o600)
            run(unsafe, 'store_failure')
            assert unsafe.read_bytes() == b'private-store-error-must-not-appear'
            symlink = root/'symlink'; symlink.symlink_to(store)
            run(symlink, 'store_failure')
            run(root, 'store_failure')
            full = root/'full'
            capacity = 16*1024*1024
            full.write_bytes((b'02'+b'00'*31+b'\n')*(capacity//65)); full.chmod(0o600)
            before = full.read_bytes()
            run(full, 'store_failure')
            assert full.read_bytes() == before
            oversized = root/'oversized'; oversized.write_bytes(b'x'*(capacity+1)); oversized.chmod(0o600)
            run(oversized, 'store_failure')
            truncated = root/'truncated'; truncated.write_bytes(b'03'+b'00'*31); truncated.chmod(0o600)
            run(truncated, 'store_failure')
            assert len(truncated.read_bytes()) == 64
            retry = root/'retry'; retry.touch(mode=0o644); retry.chmod(0o644)
            run(retry, 'store_failure')
            retry.chmod(0o600)
            run(retry, 'accepted')

            delayed = root/'held-expiry'; delayed.touch(mode=0o600)
            lock = os.open(delayed, os.O_RDWR); held.append(lock)
            fcntl.flock(lock, fcntl.LOCK_EX)
            clock.write_text('150'); marker = Path(str(clock)+'.clock'); marker.unlink(missing_ok=True)
            child = spawn(delayed)
            time.sleep(0.1)
            assert child.poll() is None and not marker.exists(), 'clock ran before held lock was acquired'
            clock.write_text('200')
            fcntl.flock(lock, fcntl.LOCK_UN); os.close(lock); held.remove(lock)
            assert result(child) == ('expired', 0, 1)
            assert delayed.read_bytes() == b''
            cases += 1

            for modes in [('accept',)*8, ('accept', 'legacy')]:
                path = root/('concurrent-'+str(len(modes))); path.touch(mode=0o600)
                lock = os.open(path, os.O_RDWR); held.append(lock); fcntl.flock(lock, fcntl.LOCK_EX)
                clock.write_text('150'); marker.unlink(missing_ok=True)
                read_gate, write_gate = os.pipe()
                try:
                    children = [spawn(path, mode, gate=read_gate) for mode in modes]
                    os.write(write_gate, b'G'*len(children))
                    time.sleep(0.1)
                    assert all(p.poll() is None for p in children) and not marker.exists(), 'concurrent lock precondition lost'
                    fcntl.flock(lock, fcntl.LOCK_UN); os.close(lock); held.remove(lock)
                    values = [result(p) for p in children]
                    assert sum(v[0] == 'accepted' for v in values) == 1
                    assert sum(v[0] == 'replay' for v in values) == len(children)-1
                    assert len(path.read_bytes()) == 65
                    cases += 1
                finally:
                    os.close(read_gate); os.close(write_gate)
            # Every clock call additionally probes the lock through a distinct
            # open description, including the non-held standalone boundary case.
        finally:
            for descriptor in held:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
            held.clear()
            for process in owned:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)
            assert all(process.poll() is not None for process in owned) and not held
    print(f'nonce acceptance cases={cases} failed=0 skipped=0 held=0 processes_remaining=0')

if __name__ == '__main__':
    main()
