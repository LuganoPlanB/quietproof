"""Exercise SDL software/dummy startup, rendering, offline fonts and close."""
import os
from pathlib import Path
import struct
import subprocess
import sys

executable = Path(sys.argv[1]).resolve()
artifacts = Path(sys.argv[2])
artifacts.mkdir(parents=True, exist_ok=True)
environment = dict(os.environ, SDL_VIDEODRIVER='dummy', SDL_RENDER_DRIVER='software',
                   XDG_DATA_HOME=str(artifacts.resolve() / 'preferences'))
checks = 0
for theme in ('light', 'dark'):
    for fallback in (False, True):
        image = artifacts / f'{theme}-{"fallback" if fallback else "inter"}.bmp'
        command = [str(executable), '--smoke-test', '--theme', theme,
                   '--screenshot', str(image)] + (['--builtin-font'] if fallback else [])
        result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        assert '3 frames; orderly SDL_QUIT' in result.stdout, result.stdout
        assert ('font=builtin' if fallback else 'font=Inter') in result.stdout, result.stdout
        data = image.read_bytes()
        assert data[:2] == b'BM'
        assert struct.unpack_from('<ii', data, 18) == (480, 720)
        offset = struct.unpack_from('<I', data, 10)[0]
        assert len(set(data[offset:])) > 10, 'Empty screenshot'
        checks += 1
for args in (['--theme', 'unknown'], ['--width', '0'], ['--font-scale', 'nan'],
             ['--height'], ['--screenshot', 'unsafe.bmp'], ['--unknown']):
    result = subprocess.run([str(executable)] + args, env=environment,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 1, args
    checks += 1
result = subprocess.run([str(executable), '--help'], env=dict(environment, SDL_VIDEODRIVER='invalid'),
                        capture_output=True, text=True, timeout=10)
assert result.returncode == 0
checks += 1
print(f'GUI lifecycle: {checks} checks passed (4 rendered lifecycles, 6 rejected arguments, headless help)')
