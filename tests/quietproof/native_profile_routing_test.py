#!/usr/bin/env python3
"""Native v4/default/explicit routing and unverified public inspection contracts."""
import argparse
import base64
import copy
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import threading

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tests'))
import signing_reference as ref
import signature_rpc_test as rpc


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--cli',required=True);parser.add_argument('--disabled',action='store_true');parser.add_argument('--rpc-enabled',choices=['ON','OFF'],default='ON');args=parser.parse_args()
    base=json.loads((ROOT/'spec/signature-profile-v1.json').read_text())['vectors'][0]['request']
    count=0
    with tempfile.TemporaryDirectory(prefix='native-profiles-') as temporary:
        root=Path(temporary)
        def run(arguments,expected=0):
            nonlocal count
            count+=1
            p=subprocess.run([args.cli,*map(str,arguments)],capture_output=True,text=True,timeout=15)
            if p.returncode!=expected: raise RuntimeError(f'case{count} exit{p.returncode} expected{expected}')
            return p
        def create(claims,extra=(),expected=0,kind=1,profile=2):
            path=root/f'request-{count}.qpr';options=[]
            for c in claims: options+=['--claim',f"{c['txid_display']}:{c['vout']}:{c['amount_sats']}:{'p2pkh' if c['script_kind'] else 'p2wpkh'}:{c['program']}"]
            p=run(['challenge','create','--network','regtest','--verifier','验证.example',
                   '--purpose','proof-of-funds','--message','exact UTF-8 ✓','--output',path,*options,*extra],expected)
            if expected:
                assert not path.exists();return None
            metadata=json.loads(p.stdout);wire=path.read_bytes()
            assert wire[:11]==b'QPS1\x04\x03\x01'+profile.to_bytes(2,'big')+bytes([1,kind])
            assert metadata['request_version']==4 and metadata['profile_version']==1
            assert metadata['signing_kind']==('p2pkh' if kind else 'p2wpkh')
            assert metadata['signing_profile']==('bitcoin-message-ecdsa-v1' if profile==2 else 'bip322-ecdsa-v1')
            offset=11
            for _ in range(2):
                size=int.from_bytes(wire[offset:offset+2],'big');offset+=2+size
            request=dict(network=3,profile=profile,profile_version=1,signing_kind=kind,verifier='验证.example',
                         purpose='proof-of-funds',nonce=wire[offset:offset+32].hex(),snapshot=None,
                         bip322_message_hash=ref.tagged('BIP0322-signed-message','exact UTF-8 ✓'.encode()).hex(),
                         not_before=metadata['request_created_at'],expires_at=metadata['expires_at'],
                         claims=sorted(claims,key=lambda c:(c['txid_display'],c['vout'])))
            assert wire==ref.request_bytes(request) and path.stat().st_mode&0o777==0o600
            inspected=json.loads(run(['inspect',path]).stdout)
            assert inspected['request_version']==4 and inspected['signing_profile']==metadata['signing_profile']
            assert inspected['proof_verified'] is False and inspected['signature_mode_available']
            material=root/f'message-{count}.txt';export=json.loads(run(['signing-material','--request',path,'--output',material]).stdout)
            digest=ref.tagged('QuietProof/statement/v4',wire)
            assert material.read_bytes()==b'quietproof:signature:v4:'+digest.hex().encode()
            assert export['signing_address']==metadata['signing_address']
            assert ('Bitcoin Signed Message' if profile==2 else 'BIP322') in export['signing_instructions']
            circuit=bytes.fromhex(metadata['approved_circuit_digest'])
            proof=b'QPE1\x04'+len(wire).to_bytes(4,'big')+wire+struct.pack('>QBHBH',metadata['request_created_at'],1,profile,1,1)+circuit+struct.pack('>IIII',1,4,128,1)+b'x'
            public=root/f'proof-{count}.qpf';public.write_bytes(proof)
            view=json.loads(run(['inspect',public]).stdout)
            assert view['circuit_approved'] and not view['proof_verified'] and view['signing_profile']==metadata['signing_profile']
            assert view['proof_bytes']==1
            old=root/f'v3-{count}.qpr';old.write_bytes(wire[:4]+b'\x03'+wire[5:])
            assert 'superseded PoSC v3' in run(['inspect',old],66).stderr
            assert 'superseded PoSC v3' in run(['signing-material','--request',old,'--output',root/'old-message'],66).stderr
            for version in [1,3]:
                receipt=root/f'old-receipt-{count}.qpa';receipt.write_bytes(b'QPA1'+bytes([version])+bytes(105));receipt.chmod(0o600)
                error=run(['prove','--request',path,'--receipt-input',receipt,'--output',root/f'old-proof-{count}.qpf'],66)
                assert 'superseded receipt' in error.stderr
            return metadata,path,request
        pkh=[copy.deepcopy(c) for c in base['claims'] if c['script_kind']==1]
        wpkh=[copy.deepcopy(c) for c in base['claims'] if c['script_kind']==0]
        if args.disabled:
            create(pkh,expected=66);create(wpkh,expected=66,kind=0,profile=1)
        else:
            legacy_metadata,legacy_path,legacy_request=create(pkh);create(wpkh,kind=0,profile=1)
            create(pkh,['--signing-profile','bip322-ecdsa-v1'],profile=1)
            create(pkh,['--signing-profile','bitcoin-message-ecdsa-v1'])
            create(wpkh,['--signing-profile','bitcoin-message-ecdsa-v1'],expected=66)
            create(pkh,['--signing-profile','future-profile'],expected=66)
            create(pkh,['--signing-kind','p2wpkh'],expected=65)
            create(base['claims'],expected=64)
            create(base['claims'],['--signing-kind','p2pkh'],expected=64)
            create(base['claims'],['--signing-profile','bitcoin-message-ecdsa-v1'],expected=64)
            create(base['claims'],['--signing-kind','p2pkh','--signing-profile','bitcoin-message-ecdsa-v1'])
            create(base['claims'],['--signing-kind','p2wpkh','--signing-profile','bip322-ecdsa-v1'],kind=0,profile=1)
            bad=copy.deepcopy(base['claims']);bad[1]['program']='01'*20
            create(bad,['--signing-kind','p2pkh','--signing-profile','bitcoin-message-ecdsa-v1'],expected=65)
            peer=rpc.Peer();thread=threading.Thread(target=peer.serve_forever,daemon=True);thread.start()
            try:
                signed=rpc.mathematical_result(legacy_request)
                peer.profile=ref.bitcoin_message_profile(legacy_request)
                peer.profile.update(legacy=True,address=ref.p2pkh_address(3,bytes.fromhex(legacy_request['claims'][0]['program'])))
                peer.pubkey=signed['pubkey'];peer.result=base64.b64encode(signed['compact']).decode();peer.wallet='selected /?'
                cookie=root/'cookie';cookie.write_text('fixture:cookie-never-print');cookie.chmod(0o600)
                receipt=root/'core-legacy.qpa'
                result=run(['authorize','--request',legacy_path,'--receipt-output',receipt,'--rpc-wallet',peer.wallet,
                            '--rpc-url',f'http://127.0.0.1:{peer.server_port}/','--rpc-cookie',cookie],0 if args.rpc_enabled=='ON' else 64)
                assert not peer.errors and 'cookie-never-print' not in result.stdout+result.stderr and peer.result not in result.stdout+result.stderr
                if args.rpc_enabled=='ON':
                    assert [m for m,_ in peer.records]==['getblockchaininfo','getwalletinfo','getaddressinfo','signmessage']
                    assert receipt.read_bytes()[:9]==b'QPA1\x04\x01\x00\x02\x01'
                    assert receipt.read_bytes()[45:]==signed['compact'] and receipt.stat().st_mode&0o777==0o600
                else: assert not receipt.exists() and not peer.records
            finally:
                peer.shutdown();peer.server_close();thread.join(timeout=2)
        create(pkh,['--proof-mode','key-knowledge','--signing-profile','bitcoin-message-ecdsa-v1'],expected=64)
        help=run(['--help']).stdout
        assert '--signing-profile' in help and 'bitcoin-message' in help and 'v4 only' in help
    print(json.dumps({'executed':count,'passed':count,'failed':0,'skipped':0,'disabled':args.disabled}))


if __name__=='__main__':
    try: main()
    except Exception as error:
        print('native profile routing failed',file=sys.stderr)
        if isinstance(error,RuntimeError): print(str(error),file=sys.stderr)
        raise SystemExit(1)
