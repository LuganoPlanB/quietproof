#!/usr/bin/env python3
"""OFFLINE, capped disposable Sparrow P2PKH funding preparation. Never broadcasts.

Only the separately invoked signet_funding.py contacts localhost Core. No wallet
creation, key export, downloads or modifications to the supplied wallet files.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

import sparrow_signer as signer

GENESIS = '00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6'
require = signer.require


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def p2pkh_script(address):
    require(isinstance(address, str) and 26 <= len(address) <= 35, 'P2PKH address required')
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    value = 0
    for char in address:
        require(char in alphabet, 'invalid Base58 address')
        value = value * 58 + alphabet.index(char)
    raw = b'\0' * (len(address) - len(address.lstrip('1'))) + value.to_bytes((value.bit_length()+7)//8, 'big')
    require(len(raw) == 25 and raw[0] == 111
            and hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] == raw[-4:],
            'test-network P2PKH checksum required')
    return '76a914' + raw[1:21].hex() + '88ac'


def transaction(raw):
    """Bounded independent wire decode; txid excludes witnesses in parent inputs."""
    require(isinstance(raw, str) and len(raw) <= 200000 and raw == raw.lower(), 'bounded hex required')
    data = bytes.fromhex(raw)
    require(data.hex() == raw, 'canonical hex required')
    offset = 0

    def take(size):
        nonlocal offset
        require(size >= 0 and offset + size <= len(data), 'truncated transaction')
        out = data[offset:offset+size]; offset += size
        return out

    def count():
        first = take(1)[0]
        if first < 253:
            return first, bytes([first])
        size = {253: 2, 254: 4, 255: 8}[first]
        buf = take(size); number = int.from_bytes(buf, 'little')
        require(number >= {253:253,254:65536,255:4294967296}[first], 'noncanonical CompactSize')
        return number, bytes([first])+buf

    version = take(4); witness = data[offset:offset+2] == b'\0\1'
    if witness:
        take(2)
    n, buf = count(); require(0 < n <= 1000, 'input count')
    stripped = version + buf; inputs = []
    for _ in range(n):
        start = offset; txid = take(32)[::-1].hex(); vout = int.from_bytes(take(4), 'little')
        size, _ = count(); script = take(size); sequence = int.from_bytes(take(4), 'little')
        stripped += data[start:offset]
        inputs.append({'txid':txid,'vout':vout,'script':script.hex(),'sequence':sequence})
    n, buf = count(); require(0 < n <= 1000, 'output count'); stripped += buf; outputs = []
    for _ in range(n):
        start = offset; amount = int.from_bytes(take(8), 'little'); size, _ = count(); script = take(size)
        require(amount <= 21000000*100000000, 'output range')
        stripped += data[start:offset]; outputs.append({'sats':amount,'script':script.hex()})
    if witness:
        for _ in inputs:
            n, _ = count(); require(n <= 1000, 'witness count')
            for _ in range(n):
                size, _ = count(); take(size)
    locktime = take(4); stripped += locktime
    require(offset == len(data), 'trailing transaction bytes')
    return {'txid':hashlib.sha256(hashlib.sha256(stripped).digest()).digest()[::-1].hex(),
            'version':int.from_bytes(version,'little'),'locktime':int.from_bytes(locktime,'little'),
            'witness':witness,'inputs':inputs,'outputs':outputs,'size':len(data)}


FIELDS = {'network','genesis','sourceTransaction','sourceTxid','sourceVout','sourceAddress',
          'sourceValueSats','changeAddress','changeScript','destinationAddress','destinationScript',
          'amountSats','feeSats'}


def validate_intent(intent):
    require(isinstance(intent, dict) and set(intent) == FIELDS, 'exact intent fields required')
    require(intent['network'] == 'signet' and intent['genesis'] == GENESIS, 'public signet required')
    for name in ['sourceVout','sourceValueSats','amountSats','feeSats']:
        require(type(intent[name]) is int, 'integer sats/index required')
    require(intent['amountSats'] == 3000 and 1 <= intent['feeSats'] <= 500
            and intent['amountSats'] + intent['feeSats'] <= 3500, 'funding authority exceeded')
    require(intent['destinationScript'] == p2pkh_script(intent['destinationAddress']), 'destination mismatch')
    require(intent['changeScript'] == p2pkh_script(intent['changeAddress']), 'change mismatch')
    require(len({intent['sourceAddress'],intent['changeAddress'],intent['destinationAddress']}) == 3,
            'distinct recipient and owned change required')
    parent = transaction(intent['sourceTransaction'])
    require(parent['txid'] == intent['sourceTxid'], 'parent txid mismatch')
    require(0 <= intent['sourceVout'] < len(parent['outputs']), 'source output missing')
    output = parent['outputs'][intent['sourceVout']]
    require(output == {'sats':intent['sourceValueSats'],'script':p2pkh_script(intent['sourceAddress'])},
            'source value/script mismatch')
    require(intent['sourceValueSats'] - intent['amountSats'] - intent['feeSats'] >= 546, 'dust change')
    return parent


def audit_transaction(intent, raw):
    validate_intent(intent)
    tx = transaction(raw)
    require(tx['version'] == 2 and tx['locktime'] == 0 and not tx['witness'], 'fixed P2PKH transaction required')
    require(len(tx['inputs']) == 1, 'single owned input required')
    inp = tx['inputs'][0]
    require(inp['txid'] == intent['sourceTxid'] and inp['vout'] == intent['sourceVout']
            and inp['sequence'] == 0xffffffff and 100 <= len(bytes.fromhex(inp['script'])) <= 108,
            'signed source mismatch')
    change = intent['sourceValueSats'] - 3000 - intent['feeSats']
    require(tx['outputs'] == [{'sats':3000,'script':intent['destinationScript']},
                             {'sats':change,'script':intent['changeScript']}], 'recipient/change mismatch')
    return {'txid':tx['txid'],'rawTransactionSha256':sha(bytes.fromhex(raw)),
            'amountSats':3000,'feeSats':intent['feeSats'],'changeSats':change,'size':tx['size'],
            'sourceTxid':intent['sourceTxid'],'sourceVout':intent['sourceVout'],
            'sourceAddress':intent['sourceAddress'],'changeAddress':intent['changeAddress'],
            'destinationAddress':intent['destinationAddress'],'network':'signet','genesis':GENESIS}


def adapter(args, action, intent=None):
    # Copy the protected wallet into a private operation directory: the stock
    # storage implementation never opens the original for writes.
    signer.private_directory(args.wallet_dir)
    marker = json.loads(signer.read_file(args.wallet_dir / signer.MARKER, private=True))
    require(marker == {'network':'signet','disposable':True}, 'disposable signet marker required')
    wallet = signer.read_file(args.wallet_dir / 'P2PKH.mv.db', private=True)
    java, cp, identity = signer.prepare(args)
    source = Path(__file__).with_name('SparrowFunding.java')
    identity['fundingAdapterSha256'] = signer.digest(source)
    identity['fundingPythonSha256'] = signer.digest(Path(__file__))
    with tempfile.TemporaryDirectory(prefix='funding-offline-', dir=args.cache) as temporary:
        stage = Path(temporary); wdir = stage / 'wallet'; wdir.mkdir(mode=0o700)
        signer.write_private(wdir / 'P2PKH.mv.db', wallet)
        classes = stage / 'classes'; classes.mkdir()
        signer.run([str(java/'javac'),'-cp',cp,'-d',str(classes),str(source)])
        command = [str(java/'java'),'--enable-native-access=ALL-UNNAMED','-Duser.home='+str(stage),
                   '-cp',cp+os.pathsep+str(classes),'SparrowFunding',action,str(wdir)]
        if intent is not None:
            path = stage/'intent.json'; signer.write_private(path,canonical(intent)); command.append(str(path))
        result = json.loads(signer.run(command,cwd=stage))
    return result, identity


def prepare(args):
    intent_bytes = signer.read_file(args.intent, private=True); intent = json.loads(intent_bytes)
    validate_intent(intent)
    # Existing bundles are immutable: no resigning, even on identical reentry.
    require(not args.output.exists() and not args.output.is_symlink(), 'new bundle directory required')
    signer.private_directory(args.output.parent)
    result, identity = adapter(args,'prepare',intent)
    raw = result.pop('rawTransaction')
    audit = audit_transaction(intent,raw)
    require(result['txid'] == audit['txid'] and result['signatureVerified'] is True, 'signer audit mismatch')
    require(all(result[k] == intent[k] for k in ['sourceAddress','changeAddress','changeScript']), 'unowned input/change')
    args.output.mkdir(mode=0o700,parents=False,exist_ok=False)
    signer.write_private(args.output/'intent.json',canonical(intent))
    signer.write_private(args.output/'signed.hex',(raw+'\n').encode())
    audit.update({'intentSha256':sha(canonical(intent)),'provenance':identity,
                  'sourceDerivation':result['sourceDerivation'],'changeDerivation':result['changeDerivation'],
                  'signatureVerified':True})
    signer.write_private(args.output/'audit.json',canonical(audit))
    return audit


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['describe','prepare'])
    for name in ['sparrow','jdk','cache','wallet-dir']:
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--intent',type=Path); parser.add_argument('--output',type=Path)
    args = parser.parse_args(argv); os.umask(0o077)
    try:
        if args.action == 'describe':
            result, identity = adapter(args,'describe'); result['provenance'] = identity
        else:
            require(args.intent and args.output,'intent and output required'); result = prepare(args)
        print(json.dumps(result,sort_keys=True)); return 0
    except (OSError,ValueError,KeyError,TypeError,IndexError,signer.subprocess.SubprocessError):
        print('Disposable funding preparation rejected; wallet/signature details withheld',file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
