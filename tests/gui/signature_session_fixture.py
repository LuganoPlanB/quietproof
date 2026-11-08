"""Disposable independent BIP322 receipt for GUI contracts; no wallet/RPC credentials."""
import copy
import os
from pathlib import Path
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'quietproof'))
import signature_rpc_test as adapter


def fixtures(root, cli):
    root.mkdir(parents=True, exist_ok=True)
    request = copy.deepcopy(adapter.core.public_profiles()['vectors'][0]['request'])
    request['signing_kind'] = 0
    request['not_before'], request['expires_at'] = int(time.time())-30, int(time.time())+3600
    signed = adapter.mathematical_result(request)
    (root/'request.qpr').write_bytes(signed['profile']['request'])
    tx = bytes.fromhex(signed['tx_hex']) if 'tx_hex' in signed else adapter.ref.serialize(signed['tx'])
    receipt = struct.pack('>4sBBH32sI', b'QPA1',1,1,1,signed['profile']['d'],len(tx))+tx
    for name,data in [('receipt.qpa',receipt),('wrong.qpa',receipt[:8]+bytes([receipt[8]^1])+receipt[9:]),
                      ('oversized.qpa',b'QPA1'+b'x'*4093)]:
        (root/name).write_bytes(data); (root/name).chmod(0o600)
    (root/'link.qpa').unlink(missing_ok=True); (root/'link.qpa').symlink_to(root/'receipt.qpa')
    (root/'fifo.qpa').unlink(missing_ok=True); os.mkfifo(root/'fifo.qpa',0o600)
    (root/'legacy.qpr').unlink(missing_ok=True)
    claim=request['claims'][0]
    subprocess.run([str(cli),'challenge','create','--proof-mode','key-knowledge','--network','regtest',
        '--claim',f"{claim['txid_display']}:{claim['vout']}:{claim['amount_sats']}:{claim['program']}",
        '--output',str(root/'legacy.qpr')],check=True,capture_output=True)


if __name__ == '__main__':
    driver,cli,root=map(Path,sys.argv[1:4]); fixtures(root,cli)
    raise SystemExit(subprocess.run([str(driver),str(root)]).returncode)
