"""Compare the typed GUI model against the real current CLI inspect command."""
import json
import os
from pathlib import Path
import subprocess
import sys

cli, driver, directory = map(lambda p: Path(p).resolve(), sys.argv[1:4])
checks = 0
environment = dict(os.environ, TZ='Pacific/Honolulu')
for path in sorted(directory.glob('*.qpr')):
    expected = subprocess.run([str(cli), 'inspect', str(path)], capture_output=True, text=True,
                              timeout=5, check=True)
    actual = subprocess.run([str(driver), '--inspect', str(path), '1800000000'],
                            capture_output=True, text=True, timeout=5, check=True, env=environment)
    model = json.loads(actual.stdout)
    assert model['inspect'] == json.loads(expected.stdout), (path.name, model, expected.stdout)
    assert model['expires_utc'].endswith('UTC') or '(UTC;' in model['expires_utc']
    if path.name == 'long.qpr':
        assert len(model['inspect']['verifier'].encode()) == 256
    if path.name == 'directional.qpr':
        assert '[U+202E]' in model['verifier_display']
        assert '\u202e' in model['inspect']['verifier']
    checks += 1
assert checks == 12, checks
print(f'GUI inspect parity: {checks} fixtures match CLI; all networks, v1/v2, mixed scripts, '
      'snapshots, bridge, long/untrusted text and huge timestamps')
