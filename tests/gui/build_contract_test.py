"""GUI configuration cannot leak SDL discovery into headless configurations."""
from pathlib import Path
import subprocess
import sys

source, work = map(Path, sys.argv[1:3])
prefix = sys.argv[3]
work.mkdir(parents=True, exist_ok=True)
common = ['cmake', '-S', str(source), '-DBUILD_TESTING=OFF',
          '-DQUIETPROOF_BUILD_CLI=OFF', '-DCMAKE_PREFIX_PATH=' + prefix]
for name, extra, failure in (
    ('requires-rpc', ['-DQUIETPROOF_BUILD_GUI=ON', '-DQUIETPROOF_BUILD_RPC=OFF'],
     'QUIETPROOF_BUILD_GUI requires'),
    ('headless', ['-DQUIETPROOF_BUILD_GUI=OFF', '-DQUIETPROOF_BUILD_RPC=OFF',
                  '-DCMAKE_DISABLE_FIND_PACKAGE_SDL2=TRUE',
                  '-DCMAKE_DISABLE_FIND_PACKAGE_CURL=TRUE'], None),
):
    result = subprocess.run(common + ['-B', str(work / name)] + extra,
                            capture_output=True, text=True, timeout=15)
    (work / (name + '.log')).write_text(result.stdout + result.stderr)
    if failure:
        assert result.returncode != 0 and failure in result.stdout + result.stderr
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        build = subprocess.run(['cmake', '--build', str(work / name)],
                               capture_output=True, text=True, timeout=10)
        assert build.returncode == 0, build.stdout + build.stderr
print('GUI build contract: 2 configurations passed; headless build passed')
