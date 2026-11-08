#!/usr/bin/env python3
"""Independent public disposable compact vectors and private native IO checks.

No wallet, network, SDK signing code, production digest or C++ codec is used to
construct vectors. Every scalar/nonce is deterministic PUBLIC test material.
"""
import argparse
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests'))
import signing_reference as ref

spec = importlib.util.spec_from_file_location('compact_math', ROOT / 'scripts/generate_signature_vectors.py')
math = importlib.util.module_from_spec(spec)
spec.loader.exec_module(math)


def legacy(request, scalar=1, nonce=2):
    key = math.compressed(math.multiply(scalar, math.G))
    request = copy.deepcopy(request)
    request.update(profile=2, profile_version=1, signing_kind=1)
    request['claims'] = [c for c in request['claims'] if c['script_kind'] == 1]
    for claim in request['claims']:
        claim['program'] = ref.hash160(key).hex()
    wire = ref.request_bytes(request)
    d = ref.tagged('QuietProof/statement/v4', wire)
    message = b'quietproof:signature:v4:' + d.hex().encode('ascii')
    # Independent Bitcoin Signed Message length framing, not transaction ALL.
    preimage = ref.varbytes(b'Bitcoin Signed Message:\n') + ref.varbytes(message)
    z = ref.sha256d(preimage)
    point = math.multiply(nonce, math.G)
    r = point[0] % math.N
    s = (int.from_bytes(z, 'big') + r * scalar) * pow(nonce, -1, math.N) % math.N
    recovery = int(point[0] >= math.N) * 2 + point[1] % 2
    if s > math.N // 2:
        s = math.N - s
        recovery ^= 1
    compact = bytes([31 + recovery]) + r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    assert math.evaluate(z, math.multiply(scalar, math.G), r, s)['valid']
    receipt = struct.pack('>4sBBHB32sI', b'QPA1', 4, 1, 2, 1, d, 65) + compact
    return request, {'request': wire.hex(), 'signature': base64.b64encode(compact).decode(),
        'receipt': receipt.hex(), 'key': key.hex(), 'r': f'{r:064x}', 's': f'{s:064x}',
        'd': d.hex(), 'z': z.hex(), 'preimage': preimage.hex(), 'expected': 'none'}


def fixtures(disabled):
    template = json.loads((ROOT / 'spec/signature-profile-v1.json').read_text())['legacy_vectors'][0]['request']
    cases = []
    for scalar in [1, math.N - 1]:
        request, good = legacy(template, scalar)
        if disabled:
            good['expected'] = 'signature_mode_disabled'
        cases.append(good)
        for transport in ['receipt', 'bip322-full']:
            other = dict(good, transport=transport)
            if transport == 'bip322-full':
                other['expected'] = 'signature_mode_disabled' if disabled else 'unsupported'
            cases.append(other)
        if disabled:
            continue
        compact = base64.b64decode(good['signature'])
        def add_signature(raw, expected):
            cases.append(dict(good, signature=base64.b64encode(raw).decode(), expected=expected))
        for header in range(256):
            if header != compact[0]:
                add_signature(bytes([header]) + compact[1:],
                              'invalid_authorization' if 31 <= header <= 34 else 'unsupported')
        for offset in [1, 33]:
            for value in [0, math.N, 2**256 - 1]:
                bad = bytearray(compact); bad[offset:offset+32] = value.to_bytes(32, 'big')
                add_signature(bad, 'invalid_authorization')
        high = bytearray(compact); high[33:] = (math.N - int(good['s'], 16)).to_bytes(32, 'big')
        add_signature(high, 'invalid_authorization')
        high[0] = 31 + ((compact[0] - 31) ^ 1)
        add_signature(high, 'invalid_authorization')
        for text in ['', good['signature']+'\n', ' '+good['signature'], good['signature']+'AAAA',
                     good['signature'][:-1], '_'*88, 'A'*89, good['signature'][:-2]+'B=', 'A'*16385]:
            cases.append(dict(good, signature=text, expected='malformed_receipt'))
        for field in ['nonce', 'network', 'verifier', 'profile', 'program', 'message']:
            bad = copy.deepcopy(request)
            if field == 'nonce': bad['nonce'] = '42'*32
            elif field == 'network': bad['network'] = 2
            elif field == 'verifier': bad['verifier'] = 'autre.example/é'
            elif field == 'profile': bad['profile'] = 1
            elif field == 'message': bad['bip322_message_hash'] = '24'*32
            else:
                for claim in bad['claims']: claim['program'] = '01'*20
            cases.append(dict(good, request=ref.request_bytes(bad).hex(),
                              expected='unsupported' if field == 'profile' else 'invalid_authorization'))
        for version in [1, 3]:
            bad = bytearray.fromhex(good['request']); bad[4] = version
            cases.append(dict(good, request=bad.hex(), expected='unsupported'))
        for offset, value in [(4, 3), (7, 1), (7, 3), (8, 2), (9, 0xff), (41, 0xff)]:
            bad = bytearray.fromhex(good['receipt']); bad[offset] = value
            expected = 'invalid_authorization' if offset == 7 and value == 1 else {
                4:'unsupported',7:'unsupported',8:'unsupported',9:'invalid_authorization',41:'malformed_receipt'}[offset]
            cases.append(dict(good, transport='receipt', receipt=bad.hex(), expected=expected))
        for size in [0, 44, 45, 109, 111, 4097]:
            raw = bytes.fromhex(good['receipt']); raw = (raw + bytes(4097))[:size]
            cases.append(dict(good, transport='receipt', receipt=raw.hex(), expected='malformed_receipt'))
    # The pure helper reconstructs fixed88-byte message framing even when the
    # committed verifier contains multiple UTF-8 code units.
    unicode_request = copy.deepcopy(template); unicode_request['verifier'] = '验证.example/é'
    _, unicode_good = legacy(unicode_request)
    if disabled: unicode_good['expected'] = 'signature_mode_disabled'
    cases.append(unicode_good)
    recovery = []
    # Force the astronomically rare x(R)=r+n branch without signing-key search.
    r = next(x for x in range(1, 100) if pow((math.N+x)**3+7, (math.P-1)//2, math.P) == 1)
    for parity in [0, 1]:
        nonce = math.lift_x(math.N+r, parity)
        for z in [0, 1, math.N, math.P, 2**256-1]:
            q = math.multiply(pow(r, -1, math.N), math.add(nonce, math.negate(math.multiply(z % math.N, math.G))))
            compact = bytes([33+parity]) + r.to_bytes(32, 'big') + (1).to_bytes(32, 'big')
            recovery.append({'compact':compact.hex(), 'z':f'{z:064x}', 'valid':True, 'key':math.compressed(q).hex()})
    return cases, recovery, template


def write(path, data):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
        stream.write(data)


def cli_checks(cli, directory, template):
    template = copy.deepcopy(template)
    template.update(not_before=int(time.time())-60, expires_at=int(time.time())+21600)
    request, good = legacy(template)
    wire = bytes.fromhex(good['request']); qpr = directory/'expected.qpr'; write(qpr, wire)
    signature = directory/'compact.txt'; write(signature, good['signature'].encode())
    message = directory/'message.txt'
    def run(args, ok):
        p = subprocess.run([cli, *map(str,args)], capture_output=True, timeout=15)
        assert (p.returncode == 0) == ok
        assert good['signature'].encode() not in p.stdout+p.stderr
        return p
    run(['signing-material','--request',qpr,'--output',message], True)
    assert message.read_bytes() == b'quietproof:signature:v4:' + good['d'].encode()
    out = directory/'receipt.qpa'
    command = ['import-signature','--request',qpr,'--signature-input',signature,
               '--signature-format','bitcoin-message','--receipt-output',out]
    run(command, True); assert out.read_bytes() == bytes.fromhex(good['receipt']) and out.stat().st_mode & 0o777 == 0o600
    run(command, False)  # Exclusive output, no replacement.
    count = 3
    wrapper = {'network':'regtest','scriptKind':'p2pkh','address':None,'format':'standard',
        'messageSha256':hashlib.sha256(message.read_bytes()).hexdigest(),'signature':good['signature'],
        'signingProfile':'bitcoin-message-ecdsa-v1','profileVersion':1}
    # The address encoder is independent Python Base58Check, not a CLI oracle.
    payload = b'\x6f'+bytes.fromhex(request['claims'][0]['program']); n = int.from_bytes(payload+ref.sha256d(payload)[:4], 'big')
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'; address = ''
    while n: n, digit = divmod(n,58); address = alphabet[digit]+address
    wrapper['address'] = address
    mutations = [None,'network','scriptKind','address','messageSha256','signingProfile','profileVersion','format']
    for index, field in enumerate(mutations):
        obj = dict(wrapper)
        if field: obj[field] = 2 if field == 'profileVersion' else 'wrong'
        path = directory/f'wrapper-{index}.json'; write(path,json.dumps(obj).encode())
        run(['import-signature','--request',qpr,'--signature-input',path,'--signature-format','sparrow-json',
             '--receipt-output',directory/f'wrapper-{index}.qpa'], field is None); count += 1
    for index, version in enumerate([1.5,-1,4294967297]):
        obj=dict(wrapper,profileVersion=version);path=directory/f'version-{index}.json';write(path,json.dumps(obj).encode())
        run(['import-signature','--request',qpr,'--signature-input',path,'--signature-format','sparrow-json',
             '--receipt-output',directory/f'version-{index}.qpa'],False);count += 1
    for label in ['electrum','bip137','bitcoin-message']:
        path=directory/(label+'.json');write(path,json.dumps(dict(wrapper,format=label)).encode())
        run(['import-signature','--request',qpr,'--signature-input',path,'--signature-format','sparrow-json',
             '--receipt-output',directory/(label+'.qpa')],True);count += 1
    for index, kind in enumerate(['public','symlink','fifo','oversized','malformed']):
        path=directory/f'unsafe-{index}'
        if kind=='symlink': path.symlink_to(signature)
        elif kind=='fifo': os.mkfifo(path,0o600)
        else:
            write(path, b'X'*16385 if kind=='oversized' else b'{"signature":"PRIVATE_DIAGNOSTIC_SENTINEL' if kind=='malformed' else good['signature'].encode())
            if kind=='public': path.chmod(0o644)
        p=run(['import-signature','--request',qpr,'--signature-input',path,'--signature-format',
               'sparrow-json' if kind=='malformed' else 'bitcoin-message','--receipt-output',directory/f'unsafe-{index}.qpa'],False)
        assert b'PRIVATE_DIAGNOSTIC_SENTINEL' not in p.stdout+p.stderr; count += 1
    return count


def frozen_vectors():
    _, recovery, template = fixtures(False)
    vectors=[]
    for name, scalar in [('compressed_even',1),('compressed_odd',math.N-1)]:
        request, vector=legacy(template,scalar)
        vectors.append({'name':name,'PUBLIC_disposable_scalar':f'{scalar:064x}',
                        'PUBLIC_disposable_nonce':2,'typed_request':request,**vector})
    return {'format':'quietproof-bitcoin-message-vectors-v1','public_test_data':True,
        'scope':'Deterministic public mathematical test signatures/receipts; no live wallet material; independent Python integer arithmetic and hashlib.',
        'vectors':vectors,'recovery':recovery}


def main():
    p=argparse.ArgumentParser();p.add_argument('--driver');p.add_argument('--cli');p.add_argument('--work',type=Path);p.add_argument('--disabled',action='store_true');p.add_argument('--emit-vectors',action='store_true');p.add_argument('--check-vectors',type=Path);args=p.parse_args()
    frozen=frozen_vectors()
    if args.emit_vectors:
        print(json.dumps(frozen,indent=2,sort_keys=True));return 0
    fixture=args.check_vectors or ROOT/'spec/bitcoin-message-vectors-v1.json'
    assert frozen==json.loads(fixture.read_text())
    if args.check_vectors:
        print('2 public compact vectors and 10 independent recovery vectors match');return 0
    if not args.driver or not args.work: p.error('--driver and --work required')
    args.work.mkdir(parents=True,exist_ok=True);directory=Path(tempfile.mkdtemp(prefix='bitcoin-message-',dir=args.work));directory.chmod(0o700)
    cases,recovery,template=fixtures(args.disabled);path=directory/'public-disposable-vectors.json';write(path,json.dumps({'cases':cases,'recovery':recovery}).encode())
    result=subprocess.run([args.driver,str(path)],capture_output=True,text=True,timeout=110)
    print(result.stdout,end='');print(result.stderr,end='')
    if result.returncode: return result.returncode
    io=cli_checks(args.cli,directory,template) if args.cli else 0
    print(json.dumps({'privateIoCases':io,'disabled':args.disabled,'failed':0,'fixtureSha256':hashlib.sha256(path.read_bytes()).hexdigest()}))
    return 0


if __name__=='__main__':
    try: sys.exit(main())
    except Exception: sys.exit('private legacy fixture or execution failed; diagnostics suppressed')
