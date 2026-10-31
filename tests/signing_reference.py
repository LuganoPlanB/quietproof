"""Independent, bounded test reference for the frozen signature profile.

Uses only Python integers/hashlib and the external public verification oracle.
Does not import the specification generator, SDK, or application codecs. This
is deliberately test-only support, not a production request or receipt API.
"""
import copy
import hashlib
import re
import subprocess


ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
FIELD = 2**256 - 2**32 - 977
GENERATOR = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
             0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def tagged(tag, data):
    prefix = hashlib.sha256(tag.encode('ascii')).digest()
    return hashlib.sha256(prefix + prefix + data).digest()


def hash160(data):
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()


def integer(value, size, order='little'):
    return value.to_bytes(size, order)


def compact(value):
    require(0 <= value <= 0xFFFFFFFFFFFFFFFF, 'CompactSize range')
    if value < 253:
        return bytes([value])
    for marker, size in ((253, 2), (254, 4), (255, 8)):
        if value < 1 << (8 * size):
            return bytes([marker]) + integer(value, size)


def varbytes(data):
    return compact(len(data)) + data


def script_for(kind, program):
    require(kind in (0, 1) and len(program) == 20, 'unsupported script profile')
    return b'\x00\x14' + program if kind == 0 else b'\x76\xa9\x14' + program + b'\x88\xac'


def request_bytes(request):
    """Construct valid test requests directly from typed public fields."""
    claims = request['claims']
    require(1 <= len(claims) <= 16, 'invalid claim count')
    require(request['signing_kind'] in [c['script_kind'] for c in claims], 'selected kind absent')
    require(len({c['program'] for c in claims}) == 1, 'claim hashes differ')
    order = [(bytes.fromhex(c['txid_display']), c['vout']) for c in claims]
    require(order == sorted(set(order)), 'claims not strictly sorted')
    require(sum(c['amount_sats'] for c in claims) <= 2100000000000000, 'claim sum range')
    def text(value):
        encoded = value.encode('utf-8')
        require(1 <= len(encoded) <= 256 and all(ord(c) >= 32 and ord(c) != 127 for c in value),
                'invalid request text')
        return integer(len(encoded), 2, 'big') + encoded
    result = b'QPS1\x03' + bytes([request['network'], 1, 0, 1, request['signing_kind']])
    result += text(request['verifier']) + text(request['purpose'])
    for name in ('nonce', 'bip322_message_hash'):
        value = bytes.fromhex(request[name])
        require(len(value) == 32 and any(value), 'invalid request commitment')
        result += value
    require(request['not_before'] < request['expires_at'], 'invalid validity interval')
    result += integer(request['not_before'], 8, 'big') + integer(request['expires_at'], 8, 'big')
    snapshot = request['snapshot']
    result += bytes([snapshot is not None])
    if snapshot is not None:
        block = bytes.fromhex(snapshot['hash_display'])
        require(len(block) == 32 and any(block), 'invalid snapshot')
        result += block + integer(snapshot['height'], 4, 'big')
    result += b'\x00' + integer(len(claims), 2, 'big')
    for claim in claims:
        txid, program = bytes.fromhex(claim['txid_display']), bytes.fromhex(claim['program'])
        require(len(txid) == 32 and any(txid) and 1 <= claim['amount_sats'] <= 2100000000000000,
                'invalid real claim')
        script_for(claim['script_kind'], program)
        result += (txid + integer(claim['vout'], 4, 'big') + integer(claim['amount_sats'], 8, 'big') +
                   bytes([claim['script_kind']]) + program)
    require(len(result) <= 4096, 'request exceeds bound')
    return result


def serialize(tx, witness=True):
    has_witness = witness and any(i['witness'] for i in tx['inputs'])
    result = integer(tx['version'], 4) + (b'\x00\x01' if has_witness else b'')
    result += compact(len(tx['inputs']))
    for item in tx['inputs']:
        result += item['outpoint'] + varbytes(item['script']) + integer(item['sequence'], 4)
    result += compact(len(tx['outputs']))
    for item in tx['outputs']:
        result += integer(item['amount'], 8) + varbytes(item['script'])
    if has_witness:
        for item in tx['inputs']:
            result += compact(len(item['witness'])) + b''.join(varbytes(w) for w in item['witness'])
    return result + integer(tx['locktime'], 4)


class Reader:
    def __init__(self, raw):
        self.raw, self.position = raw, 0

    def take(self, size):
        require(size >= 0 and self.position + size <= len(self.raw), 'truncated transaction')
        value = self.raw[self.position:self.position + size]
        self.position += size
        return value

    def number(self, size):
        return int.from_bytes(self.take(size), 'little')

    def count(self, maximum):
        first = self.number(1)
        value = first
        if first >= 253:
            size = {253: 2, 254: 4, 255: 8}[first]
            value = self.number(size)
            require(value >= {253: 253, 254: 65536, 255: 4294967296}[first],
                    'nonminimal CompactSize')
        require(value <= maximum, 'transaction count/length exceeds bound')
        return value

    def blob(self):
        return self.take(self.count(4096))


def parse_transaction(raw):
    require(10 <= len(raw) <= 4096, 'transaction size bound')
    reader = Reader(raw)
    version = reader.number(4)
    count = reader.count(64)
    witness = count == 0
    if witness:
        require(reader.take(1) == b'\x01', 'invalid witness marker/flag')
        count = reader.count(64)
    require(count > 0, 'empty inputs')
    inputs = []
    for _ in range(count):
        inputs.append({'outpoint': reader.take(36), 'script': reader.blob(),
                       'sequence': reader.number(4), 'witness': ()})
    outputs = []
    for _ in range(reader.count(64)):
        outputs.append({'amount': reader.number(8), 'script': reader.blob()})
    if witness:
        for item in inputs:
            item['witness'] = tuple(reader.blob() for _ in range(reader.count(64)))
        require(any(i['witness'] for i in inputs), 'superfluous witness serialization')
    locktime = reader.number(4)
    require(reader.position == len(raw), 'trailing transaction bytes')
    tx = {'version': version, 'inputs': inputs, 'outputs': outputs, 'locktime': locktime}
    require(serialize(tx) == raw, 'noncanonical transaction serialization')
    return tx


def digest_preimage(tx, kind, program, amount=0, index=0, sighash=1):
    # Extended only for real-spend negative controls. The virtual profile and
    # receipt validator still require ALL exactly. SINGLE's historical
    # out-of-range special result is intentionally outside these fixtures.
    require(sighash in (1, 2, 3, 129), 'unsupported reference sighash')
    base, anyone = sighash & 31, bool(sighash & 128)
    require(0 <= index < len(tx['inputs']) and (base != 3 or index < len(tx['outputs'])),
            'unsupported reference input/output index')
    script = script_for(1, program)
    if kind == 1:
        legacy = copy.deepcopy(tx)
        for position, item in enumerate(legacy['inputs']):
            item['script'] = script if position == index else b''
            item['witness'] = ()
            if position != index and base in (2, 3):
                item['sequence'] = 0
        if base == 2:
            legacy['outputs'] = []
        elif base == 3:
            legacy['outputs'] = ([{'amount': 0xFFFFFFFFFFFFFFFF, 'script': b''} for _ in range(index)] +
                                 [copy.deepcopy(tx['outputs'][index])])
        if anyone:
            legacy['inputs'] = [legacy['inputs'][index]]
        return serialize(legacy, witness=False) + integer(sighash, 4)
    require(kind == 0, 'unsupported reference kind')
    item = tx['inputs'][index]
    def output_bytes(output):
        return integer(output['amount'], 8) + varbytes(output['script'])
    output_hash = (sha256d(b''.join(output_bytes(o) for o in tx['outputs'])) if base == 1 else
                   sha256d(output_bytes(tx['outputs'][index])) if base == 3 else bytes(32))
    prevout_hash = bytes(32) if anyone else sha256d(b''.join(i['outpoint'] for i in tx['inputs']))
    sequence_hash = (bytes(32) if anyone or base in (2, 3) else
                     sha256d(b''.join(integer(i['sequence'], 4) for i in tx['inputs'])))
    return (integer(tx['version'], 4) + prevout_hash + sequence_hash + item['outpoint'] +
            varbytes(script) + integer(amount, 8) + integer(item['sequence'], 4) + output_hash +
            integer(tx['locktime'], 4) + integer(sighash, 4))


def virtual_profile(request):
    canonical = request_bytes(request)
    d = tagged('QuietProof/statement/v3', canonical)
    message = b'quietproof:signature:v1:' + d.hex().encode('ascii')
    m = tagged('BIP0322-signed-message', message)
    kind, program = request['signing_kind'], bytes.fromhex(request['claims'][0]['program'])
    selected = script_for(kind, program)
    parent = {'version': 0, 'locktime': 0, 'inputs': [{
        'outpoint': bytes(32) + b'\xff' * 4, 'script': b'\x00\x20' + m,
        'sequence': 0, 'witness': ()}], 'outputs': [{'amount': 0, 'script': selected}]}
    parent_bytes = serialize(parent)
    parent_id = sha256d(parent_bytes)
    tx = {'version': 0, 'locktime': 0, 'inputs': [{
        'outpoint': parent_id + bytes(4), 'script': b'', 'sequence': 0, 'witness': ()}],
        'outputs': [{'amount': 0, 'script': b'\x6a'}]}
    preimage = digest_preimage(tx, kind, program)
    return {'request': canonical, 'd': d, 'message': message, 'm': m,
            'script': selected, 'parent': parent_bytes, 'parent_id': parent_id,
            'unsigned': serialize(tx), 'tx': tx, 'preimage': preimage, 'z': sha256d(preimage)}


def strict_signature(signature, allowed_sighashes=(1,)):
    require(9 <= len(signature) <= 72 and signature[-1] in allowed_sighashes, 'signature size/sighash')
    der = signature[:-1]
    require(der[0] == 0x30 and der[1] == len(der) - 2, 'invalid DER sequence')
    reader = Reader(der[2:])
    values = []
    for _ in range(2):
        require(reader.take(1) == b'\x02', 'invalid DER integer tag')
        raw = reader.take(reader.number(1))
        require(1 <= len(raw) <= 33 and not raw[0] & 0x80, 'invalid DER integer')
        require(len(raw) == 1 or raw[0] != 0 or raw[1] & 0x80, 'nonminimal DER integer')
        values.append(int.from_bytes(raw, 'big'))
    require(reader.position == len(reader.raw), 'trailing DER bytes')
    r, s = values
    require(1 <= r < ORDER and 1 <= s <= ORDER // 2, 'signature scalar range/low-S')
    return r, s


def oracle_verify(oracle, digest, signature, pubkey):
    try:
        result = subprocess.run([str(oracle), digest.hex(), signature[:-1].hex(), pubkey.hex()],
                                capture_output=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        # TimeoutExpired includes argv, hence witness material, in its text.
        raise RuntimeError('oracle execution failed') from None
    require(result.returncode in (0, 1), 'oracle execution failed')
    require(result.stdout == (b'valid\n' if result.returncode == 0 else b'invalid\n'),
            'oracle response malformed')
    return result.returncode == 0


def integer_verify(digest, signature, pubkey, *, sighash=1):
    """Variable-time independent integer ECDSA, only for public test fixtures."""
    r, s = strict_signature(signature, allowed_sighashes=(sighash,))
    if len(digest) != 32 or len(pubkey) != 33 or pubkey[0] not in (2, 3):
        return False
    x = int.from_bytes(pubkey[1:], 'big')
    if x >= FIELD:
        return False
    square = (x**3 + 7) % FIELD
    y = pow(square, (FIELD + 1) // 4, FIELD)
    if y * y % FIELD != square:
        return False
    if y % 2 != pubkey[0] % 2:
        y = FIELD - y
    def add(left, right):
        if left is None:
            return right
        if right is None:
            return left
        a, b = left
        c, d = right
        if a == c and (b != d or b == 0):
            return None
        slope = ((3 * a * a) * pow(2 * b, -1, FIELD) if left == right else
                 (d - b) * pow(c - a, -1, FIELD)) % FIELD
        xx = (slope * slope - a - c) % FIELD
        return xx, (slope * (a - xx) - b) % FIELD
    def multiply(scalar, point):
        result = None
        while scalar:
            if scalar & 1:
                result = add(result, point)
            point = add(point, point)
            scalar >>= 1
        return result
    inverse = pow(s, -1, ORDER)
    point = add(multiply(int.from_bytes(digest, 'big') * inverse % ORDER, GENERATOR),
                multiply(r * inverse % ORDER, (x, y)))
    return point is not None and point[0] % ORDER == r


def extract_unlock(tx, kind, index=0, allowed_sighashes=(1,)):
    item = tx['inputs'][index]
    if kind == 1:
        require(not item['witness'], 'unexpected P2PKH witness')
        reader = Reader(item['script'])
        size = reader.number(1)
        require(1 <= size <= 75, 'nonminimal signature push')
        signature = reader.take(size)
        require(reader.take(1) == b'\x21', 'noncanonical public-key push')
        pubkey = reader.take(33)
        require(reader.position == len(reader.raw), 'extra scriptSig data')
    else:
        require(not item['script'] and len(item['witness']) == 2, 'noncanonical witness stack')
        signature, pubkey = item['witness']
    require(len(pubkey) == 33 and pubkey[0] in (2, 3), 'expected compressed public key')
    r, s = strict_signature(signature, allowed_sighashes=allowed_sighashes)
    return signature, pubkey, r, s


def validate_signed_response(request, response, oracle):
    require(isinstance(response, dict) and response.get('complete') is True,
            'wallet signing incomplete')
    require(not response.get('errors'), 'wallet signing response contains errors')
    encoded = response.get('hex')
    require(isinstance(encoded, str) and len(encoded) <= 8192 and
            re.fullmatch('[0-9a-f]+', encoded) and len(encoded) % 2 == 0,
            'invalid signed transaction hex')
    tx = parse_transaction(bytes.fromhex(encoded))
    profile = virtual_profile(request)
    require(len(tx['inputs']) == 1 and len(tx['outputs']) == 1, 'changed virtual transaction shape')
    stripped = copy.deepcopy(tx)
    stripped['inputs'][0]['script'], stripped['inputs'][0]['witness'] = b'', ()
    require(serialize(stripped) == profile['unsigned'], 'changed unsigned transaction fields')
    signature, pubkey, r, s = extract_unlock(tx, request['signing_kind'])
    program = bytes.fromhex(request['claims'][0]['program'])
    require(hash160(pubkey) == program, 'public key does not match request')
    require(integer_verify(profile['z'], signature, pubkey), 'integer signature verification failed')
    require(oracle_verify(oracle, profile['z'], signature, pubkey), 'independent signature verification failed')
    return {'tx': tx, 'signature': signature, 'pubkey': pubkey, 'r': r, 's': s, 'profile': profile}
