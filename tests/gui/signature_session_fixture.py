"""Public disposable profile vectors for private GUI receipt IO; no wallet/RPC credentials."""
import copy
import os
from pathlib import Path
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'quietproof'))
import signature_rpc_test as adapter
from bitcoin_message_test import legacy


def fixtures(root, cli, profile='bip322-p2wpkh'):
    root.mkdir(parents=True, exist_ok=True)
    kind = 0 if profile == 'bip322-p2wpkh' else 1
    request = copy.deepcopy(next(v['request'] for v in adapter.core.public_profiles()['vectors'] if v['request']['signing_kind'] == kind))
    request['signing_kind'] = kind
    request['not_before'], request['expires_at'] = int(time.time())-30, int(time.time())+3600
    if profile == 'bitcoin-message-p2pkh':
        request, signed = legacy(request)
        wire, receipt = bytes.fromhex(signed['request']), bytes.fromhex(signed['receipt'])
    else:
        signed = adapter.mathematical_result(request)
        wire = signed['profile']['request']
        tx = bytes.fromhex(signed['tx_hex']) if 'tx_hex' in signed else adapter.ref.serialize(signed['tx'])
        receipt = struct.pack('>4sBBHB32sI', b'QPA1',4,1,1,1,signed['profile']['d'],len(tx))+tx
    (root/'request.qpr').write_bytes(wire)
    wrong_profile=bytearray(receipt); wrong_profile[7]=1 if request['profile']==2 else 2
    old_receipt=bytearray(receipt);old_receipt[4]=3
    for name,data in [('receipt.qpa',receipt),('wrong.qpa',receipt[:8]+bytes([receipt[8]^1])+receipt[9:]),
                      ('wrong-profile.qpa',wrong_profile),('v3.qpa',old_receipt),
                      ('oversized.qpa',b'QPA1'+b'x'*4093)]:
        (root/name).write_bytes(data); (root/name).chmod(0o600)
    (root/'link.qpa').unlink(missing_ok=True); (root/'link.qpa').symlink_to(root/'receipt.qpa')
    (root/'fifo.qpa').unlink(missing_ok=True); os.mkfifo(root/'fifo.qpa',0o600)
    nonce=11
    for _ in range(2):nonce+=2+struct.unpack_from('>H',wire,nonce)[0]
    other=bytearray(wire);other[nonce]^=1;(root/'other-request.qpr').write_bytes(other)
    for name, offset, value in [('v3',4,3),('unknown-profile',8,255),('future-profile',9,2)]:
        changed=bytearray(wire);changed[offset]=value;(root/(name+'.qpr')).write_bytes(changed)
    (root/'legacy.qpr').unlink(missing_ok=True)
    claim=request['claims'][0]
    subprocess.run([str(cli),'challenge','create','--proof-mode','key-knowledge','--network','regtest',
        '--claim',f"{claim['txid_display']}:{claim['vout']}:{claim['amount_sats']}:{claim['program']}",
        '--output',str(root/'legacy.qpr')],check=True,capture_output=True)


if __name__ == '__main__':
    driver,cli,root=map(Path,sys.argv[1:4])
    for profile in ['bitcoin-message-p2pkh','bip322-p2wpkh','bip322-p2pkh']:
        directory=root/profile;fixtures(directory,cli,profile)
        result=subprocess.run([str(driver),str(directory),*sys.argv[4:]])
        if result.returncode:raise SystemExit(result.returncode)
