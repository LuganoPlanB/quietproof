#!/usr/bin/env python3
"""Private local receipt parser corpus; independent L2 construction and optional Core32 signing."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import signing_reference as ref
import bitcoin_core_signing_regtest as core

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--driver',required=True)
parser.add_argument('--disabled',action='store_true')
parser.add_argument('--work',type=Path,required=True)
parser.add_argument('--core32',type=Path)
parser.add_argument('--oracle',type=Path)
args=parser.parse_args()
ROOT=Path(__file__).resolve().parents[2]
PROFILE=json.loads((ROOT/'spec/signature-profile-v1.json').read_text())
CASES=[]


def frame(tx,digest,version=1,mode=1,profile=1):
    return struct.pack('>4sBBH32sI',b'QPA1',version,mode,profile,digest,len(tx))+tx


def add(name,request,receipt,expected,positive=None):
    row={'name':name,'request':request.hex(),'receipt':receipt.hex(),'expected':expected}
    if positive:
        row.update(key=positive['pubkey'].hex(),r=f"{positive['r']:064x}",s=f"{positive['s']:064x}",
                   d=positive['profile']['d'].hex())
    CASES.append(row)


def corpus(request,result):
    kind=request['signing_kind']; p=result['profile']; tx=result['tx']; signed=ref.serialize(tx)
    canonical=p['request']; receipt=frame(signed,p['d'])
    valid='signature_mode_disabled' if args.disabled else 'none'
    invalid='signature_mode_disabled' if args.disabled else 'invalid_authorization'
    add('positive',canonical,receipt,valid,result)
    add('unsigned',canonical,frame(p['unsigned'],p['d']),'malformed_receipt')
    add('json-wrapper',canonical,b'{"complete":true,"hex":"not-a-binary-receipt"}', 'malformed_receipt')
    for n in range(len(receipt)):
        add('truncate-'+str(n),canonical,receipt[:n],'malformed_receipt')
    for size in [4096,4097]:
        add('file-bound-'+str(size),canonical,receipt+bytes(size-len(receipt)),'malformed_receipt')
    add('complete-4096-frame',canonical,frame(bytes(4052),p['d']),'malformed_receipt')
    add('unknown-id-before-body',canonical,frame(bytes(4052),p['d'],version=2),'unsupported')
    for declared in [0,1,4052,4053,0xffffffff]:
        changed=bytearray(receipt); changed[40:44]=declared.to_bytes(4,'big')
        add('declared-length',canonical,changed,'malformed_receipt')
    for offset,value in [(0,0),(4,2),(5,2),(6,1),(7,2)]:
        changed=bytearray(receipt); changed[offset]=value
        add('header-id',canonical,changed,'malformed_receipt' if offset==0 else 'unsupported')
    changed=bytearray(receipt); changed[5]=0
    add('known-mode',canonical,changed,'malformed_receipt')
    changed=bytearray(receipt); changed[4]=2; changed[40:44]=(0xffffffff).to_bytes(4,'big')
    add('outer-framing-precedence',canonical,changed,'malformed_receipt')
    changed=bytearray(receipt); changed[8]^=1
    add('wrong-d',canonical,changed,invalid)
    changed_request=copy.deepcopy(request); changed_request['nonce']='ff'+changed_request['nonce'][2:]
    add('changed-expected-request',ref.request_bytes(changed_request),receipt,invalid)
    rebound=ref.virtual_profile(changed_request)
    stale=copy.deepcopy(tx); stale['inputs'][0]['outpoint']=rebound['tx']['inputs'][0]['outpoint']
    add('rewritten-d-and-outpoint-stale-signature',rebound['request'],frame(ref.serialize(stale),rebound['d']),invalid)
    other=copy.deepcopy(request); other['signing_kind']^=1
    add('wrong-expected-kind',ref.request_bytes(other),frame(signed,ref.virtual_profile(other)['d']),invalid)
    other_profile=ref.virtual_profile(other)
    stale=core.replace_unlock(other_profile['tx'],other['signing_kind'],result['signature'],result['pubkey'])
    add('rewritten-kind-stale-signature',other_profile['request'],frame(ref.serialize(stale),other_profile['d']),invalid)
    changed=bytearray(canonical); changed[8]=2
    add('unknown-expected-profile',changed,receipt,'unsupported')
    add('missing-expected',b'',receipt,'malformed_statement')

    def body(name,data,classification):
        # Tighter complete transaction bounds precede authorization semantics.
        if not (108 if kind==0 else 105)<=len(data)<=(171 if kind==0 else 168):
            classification='malformed_receipt'
        add(name,canonical,frame(data,p['d']),classification)

    semantic={'changed-version','changed-locktime','changed-sequence','changed-outpoint','changed-vout',
              'changed-output-amount','changed-output-script','high-S','zero-r','zero-s','order-r','order-s',
              'wrong-key-parity','sighash-0','sighash-2','sighash-3','sighash-129'}
    for name,response in core.malformed_responses(result,kind):
        if not isinstance(response,dict) or not isinstance(response.get('hex'),str): continue
        try: raw=bytes.fromhex(response['hex'])
        except ValueError: continue
        if raw==signed: continue # RPC complete/errors flags are not receipt fields.
        if len(raw)>4052:continue
        body(name,raw,invalid if name in semantic else 'malformed_receipt')

    # Structurally valid but unauthorized keys/signatures, with h rebound when
    # needed so invalid point/range checks cannot be masked by HASH160 mismatch.
    def key_case(name,key,rebind=False):
        changed=core.replace_unlock(tx,kind,result['signature'],key)
        if not rebind:
            body(name,ref.serialize(changed),invalid); return
        altered=copy.deepcopy(request)
        for claim in altered['claims']:claim['program']=ref.hash160(key).hex()
        profile=ref.virtual_profile(altered)
        changed['inputs'][0]['outpoint']=profile['tx']['inputs'][0]['outpoint']
        add(name,profile['request'],frame(ref.serialize(changed),profile['d']),invalid)
    key_case('key-substitution',bytes([result['pubkey'][0]^1])+result['pubkey'][1:])
    key_case('noncanonical-x-p',b'\x02'+ref.FIELD.to_bytes(32,'big'),True)
    key_case('noncanonical-x-max',b'\x03'+b'\xff'*32,True)
    key_case('non-residue-x',b'\x02'+bytes(32),True)
    key_case('invalid-sec-prefix',b'\x04'+result['pubkey'][1:],True)
    wrong=core.encode_signature(result['r'], result['s']^1)
    body('wrong-signature',ref.serialize(core.replace_unlock(tx,kind,wrong,result['pubkey'])),invalid)
    # Truncating these oversized integers would recover the original VALID
    # signature, so rejection cannot be masked by an unrelated bad signature.
    for name,r,s in [('overflow-r',2**256+result['r'],result['s']),
                     ('overflow-s',result['r'],2**256+result['s'])]:
        signature=core.encode_signature(r,s)
        body(name,ref.serialize(core.replace_unlock(tx,kind,signature,result['pubkey'])),invalid)
    for name,signature in [('empty-r-in-bounds',b'\x30\x06\x02\x00\x02\x02\x01\x01\x01'),
                           ('required-r-padding',core.encode_signature(2**255,1)),
                           ('required-s-padding',core.encode_signature(1,128)),
                           ('maximum-shape-DER',core.encode_signature(2**255,ref.ORDER//2)),
                           ('in-bounds-high-S',core.encode_signature(1,ref.ORDER-1))]:
        body(name,ref.serialize(core.replace_unlock(tx,kind,signature,result['pubkey'])),
             'malformed_receipt' if name=='empty-r-in-bounds' else invalid)
    # Direct pushes and all CompactSizes must be minimal, not just parseable.
    # Locate the single zero output's one-byte script length without trusting
    # production offsets: independent serialization of the input prefix.
    raw=signed
    marker=2 if kind==0 else 0
    scriptlen=len(tx['inputs'][0]['script'])
    output_count=4+marker+1+36+len(ref.varbytes(tx['inputs'][0]['script']))+4
    for name,offset,value in [('nonminimal-output-count',output_count,b'\xfd\x01\x00'),
                              ('nonminimal-output-script',output_count+1+8,b'\xfd\x01\x00'),
                              ('nonminimal-scriptSig-length',4+marker+1+36,b'\xfd'+scriptlen.to_bytes(2,'little'))]:
        body(name,raw[:offset]+value+raw[offset+1:],'malformed_receipt')
    # Short canonical DER provides headroom: these mutations stay inside the
    # tight transaction cap, so bounds alone cannot mask nonminimal parsing.
    short_tx=core.replace_unlock(tx,kind,core.encode_signature(1,1),result['pubkey'])
    short=ref.serialize(short_tx)
    body('short-invalid-signature-control',short,invalid)
    short_script=len(short_tx['inputs'][0]['script'])
    short_output=4+marker+1+36+len(ref.varbytes(short_tx['inputs'][0]['script']))+4
    positions=[(4+marker,b'\xfd\x01\x00'),(41+marker,b'\xfd'+short_script.to_bytes(2,'little')),
               (short_output,b'\xfd\x01\x00'),(short_output+9,b'\xfd\x01\x00')]
    if kind==0:
        witness_offset=len(ref.serialize(short_tx,witness=False))-4+2
        positions.extend([(witness_offset,b'\xfd\x02\x00'),(witness_offset+1,b'\xfd\x09\x00'),
                          (witness_offset+11,b'\xfd\x21\x00')])
    for index,(offset,value) in enumerate(positions):
        body('short-nonminimal-'+str(index),short[:offset]+value+short[offset+1:],'malformed_receipt')
    count_offset=4+marker
    for index,value in enumerate([b'\xfd\xfd\x00', b'\xfe\x01\x00\x00\x00',
                                  b'\xfe\x00\x00\x01\x00', b'\xff'+(1).to_bytes(8,'little'),
                                  b'\xff'+(2**32).to_bytes(8,'little'), b'\xff'+b'\xff'*8]):
        body('bounded-compactsize-'+str(index),short[:count_offset]+value+short[count_offset+1:],
             'malformed_receipt')
    body('trailing-canonical-body',raw+b'\x00','malformed_receipt')
    # A body with fixed fields changed is structurally valid. Even in disabled
    # builds it must not reach native cryptographic verification.
    if args.oracle:
        assert ref.oracle_verify(args.oracle,p['z'],result['signature'],result['pubkey'])


def mathematical_result(request,odd):
    p=ref.virtual_profile(request); d=ref.ORDER-1 if odd else 1; r=ref.GENERATOR[0]
    s=(int.from_bytes(p['z'],'big')+r*d)%ref.ORDER
    s=min(s,ref.ORDER-s)
    key=bytes([3 if odd else 2])+ref.GENERATOR[0].to_bytes(32,'big')
    signature=core.encode_signature(r,s)
    assert ref.integer_verify(p['z'],signature,key)
    return {'tx':core.replace_unlock(p['tx'],request['signing_kind'],signature,key),
            'signature':signature,'pubkey':key,'r':r,'s':s,'profile':p}


def populate(node=None):
    for odd in [False,True]:
        wallet=core.fixture_wallet(node,'receipt-'+str(int(odd)),odd) if node else None
        key=bytes([3 if odd else 2])+ref.GENERATOR[0].to_bytes(32,'big')
        for vector in PROFILE['vectors']:
            request=copy.deepcopy(vector['request'])
            for claim in request['claims']:claim['program']=ref.hash160(key).hex()
            result=core.authorize(node,request,wallet['wallet'],args.oracle) if node else mathematical_result(request,odd)
            corpus(request,result)


def main():
    if args.core32:
        if args.disabled or not args.oracle:raise RuntimeError('Core qualification requires enabled driver and test oracle')
        core.validate_inputs(args.core32,args.oracle)
        with core.Node(args.core32) as node:populate(node)
    else:populate()
    math=[]
    vectors=json.loads((ROOT/'spec/signature-vectors.json').read_text())
    for case in vectors['relation_cases']:
        wire=case['oracle_input']
        if wire is None or any(int(case[field],16)>=2**256 for field in ['r','s']):continue
        math.append({'z':case['z'],'key':wire['Q_compressed'],'r':f"{int(case['r'],16):064x}",
                     's':f"{int(case['s'],16):064x}",'valid':case['expected']['valid']})
    args.work.mkdir(parents=True,exist_ok=True)
    directory=Path(tempfile.mkdtemp(prefix='private-receipt-',dir=args.work))
    path=directory/'cases.json'
    descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(descriptor,'w') as stream:json.dump({'cases':CASES,'math':math},stream)
    # The private driver receives paths only and emits bounded diagnostics.
    # The optional oracle retains L2's public-fixture API. Keep owner-only data
    # for same-run reproduction; never publish or log its receipt contents.
    process=subprocess.run([args.driver,str(path)],capture_output=True,text=True,timeout=90)
    sys.stdout.write(process.stdout); sys.stderr.write(process.stderr)
    print('Private corpus metadata: '+json.dumps({'path':str(path),'bytes':path.stat().st_size,
          'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'mode':oct(path.stat().st_mode&0o777),
          'cases':len(CASES),'math_cases':len(math),'core32':bool(args.core32)}),flush=True)
    return process.returncode


if __name__=='__main__':
    try:sys.exit(main())
    except Exception:sys.exit('private receipt test fixture or execution failed')
