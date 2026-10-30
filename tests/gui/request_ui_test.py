"""Exercise real SDL request entry, chooser cancellation, replacement and errors."""
import itertools
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

executable, fixtures, artifacts = map(lambda p: Path(p).resolve(), sys.argv[1:4])
artifacts.mkdir(parents=True, exist_ok=True)
checks = 0
with tempfile.TemporaryDirectory(prefix='quietproof-request-') as temporary:
    environment = dict(os.environ, SDL_VIDEODRIVER='dummy', SDL_RENDER_DRIVER='software',
                       XDG_DATA_HOME=temporary)

    def run(name, args=(), events=()):
        global checks
        script = artifacts / (name + '.events')
        script.write_text('\n'.join(events))
        image = artifacts / (name + '.bmp')
        command = [str(executable), '--smoke-test', '--screenshot', str(image),
                   '--test-events', str(script), *map(str, args)]
        result = subprocess.run(command, capture_output=True, text=True, env=environment, timeout=10)
        (artifacts / (name + '.log')).write_text(result.stdout + result.stderr)
        assert result.returncode == 0, (name, result.stderr)
        match = re.search(r'GUI request: loaded=(\d) error=(\d+) revision=(\d+) chooser=(\d) prove=disabled', result.stdout)
        assert match, result.stdout
        state = tuple(map(int, match.groups()))
        controls = {int(row[0]): tuple(map(float, row[1:])) for row in
                    re.findall(r'^control (\d+) ([\d.-]+) ([\d.-]+) ([\d.-]+) ([\d.-]+)$', result.stdout, re.M)}
        width, height = struct.unpack_from('<ii', image.read_bytes(), 18)
        for identifier in (1, 2, 3, 4, 11):
            x, y, w, h = controls[identifier]
            assert 0 <= x < x + w <= width and 0 <= y < y + h <= height, (name, identifier)
        checks += 1
        return state

    for theme, size, scale, screen in itertools.product(
            ('light', 'dark'), ((400, 640), (480, 720)), ('1', '1.5'), ('open', 'error')):
        width, height = size
        args = ['--theme', theme, '--width', width, '--height', height, '--font-scale', scale,
                '--request', fixtures / ('valid-v1.qpr' if screen == 'open' else 'malformed.qpr')]
        events = ['tab'] * 4 + ['enter'] if screen == 'open' else []
        state = run(f'{screen}-{theme}-{width}x{height}-{scale}', args, events)
        assert state == ((1, 0, 1, 1) if screen == 'open' else (0, 5, 1, 0)), state

    path = str(fixtures / 'valid-v2.qpr')
    text_events = ['text ' + path[i:i+24] for i in range(0, len(path), 24)]
    assert run('path-entry', events=['tab'] * 3 + text_events + ['enter']) == (1, 0, 1, 0)
    unicode_path = str(fixtures / 'Prüfung-東京.qpr')
    unicode_events = ['text ' + unicode_path[i:i+8] for i in range(0, len(unicode_path), 8)]
    assert run('unicode-path-entry', events=['tab'] * 3 + unicode_events + ['enter']) == (1, 0, 1, 0)
    run('edit-then-display', ['--theme', 'light'],
        ['tab'] * 3 + ['text a', 'click 400 35'] + ['tab'] * 5 + ['enter'])
    assert 'view=settings theme=dark' in (artifacts / 'edit-then-display.log').read_text()
    assert run('chooser-cancel', ['--request', fixtures / 'valid-v1.qpr'],
               ['tab'] * 4 + ['enter', 'tab', 'tab', 'enter']) == (1, 0, 1, 0)
    assert run('chooser-escape', events=['tab'] * 4 + ['enter', 'escape']) == (0, 0, 0, 0)
    assert run('replace-invalid', ['--request', fixtures / 'valid-v1.qpr'],
               ['drop ' + str(fixtures / 'malformed.qpr')]) == (0, 5, 2, 0)
    assert run('drop-unicode', events=['drop ' + str(fixtures / 'Prüfung-東京.qpr')]) == (1, 0, 1, 0)
    assert run('proof-file', ['--request', fixtures / 'proof-v2.qpf']) == (0, 3, 1, 0)
    assert run('oversized', ['--request', fixtures / 'oversized.qpr']) == (0, 2, 1, 0)
    # The first sorted file is selectable through the actual chooser controls.
    selection = Path(temporary) / 'choose'
    selection.mkdir()
    (selection / 'a.qpr').write_bytes((fixtures / 'valid-v1.qpr').read_bytes())
    assert run('chooser-select', ['--request', selection / 'a.qpr'],
               ['tab'] * 4 + ['enter', 'tab', 'tab', 'tab', 'enter']) == (1, 0, 2, 0)

print(f'GUI request UI: {checks} rendered checks passed; 16 open/error matrix captures, '
      'path entry, chooser select/cancel, SDL drop, replacement and disabled proving')
