#!/usr/bin/env python3
"""Cross-check Sage PoSC vectors with Python and actual composed C++ assertions.

This does not produce fresh malicious proofs or exercise the waived integrated
advice-attack gate. All witnesses are PUBLIC deterministic mathematical tuples.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check(fixture, circuit):
    document = json.loads(fixture.read_text())
    require(document['format'] == 'quietproof-posc-sage-v1' and document['public_test_data'] is True, 'fixture identity')
    require(document['sage_version'] == '10.6', 'Sage version')
    spec = importlib.util.spec_from_file_location('posc_python_crosscheck', ROOT / 'scripts/generate_signature_vectors.py')
    reference = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reference)
    corpus = json.loads((ROOT / 'spec/signature-vectors.json').read_text())
    ids = [c['id'] for c in document['cases']]
    require(len(ids) == len(set(ids)), 'duplicate case')
    require({c['id'] for c in corpus['relation_cases']} <= set(ids), 'missing independent corpus cases')
    require(len(ids) == len(corpus['relation_cases']) + 74, 'missing/extra PoSC composition cases')
    expected, rows, unrepresentable = {}, [], []
    for case in document['cases']:
        q = case['Q']
        point = None if q is None else tuple(int(q[k], 16) for k in ('x', 'y'))
        digest, public_hash = bytes.fromhex(case['z']), bytes.fromhex(case['h'])
        r, s = int(case['r'], 16), int(case['s'], 16)
        python = reference.evaluate(digest, point, r, s)
        valid = python['valid']
        if valid:
            compressed = reference.compressed(point)
            valid = len(public_hash) == 20 and hashlib.new('ripemd160', hashlib.sha256(compressed).digest()).digest() == public_hash
        require(type(case['expected']['valid']) is bool and valid == case['expected']['valid'], 'Sage/Python mismatch: ' + case['id'])
        representable = (q is not None and len(digest) == 32 and len(public_hash) == 20
                         and all(0 <= v < 2**256 for v in (*point, r, s)))
        require(representable == case['circuit_input_representable'], 'input classification: ' + case['id'])
        if not representable:
            unrepresentable.append(case['id'])
            continue
        rows.append(' '.join([case['id'], case['z'], q['x'], q['y'], case['r'], case['s'], case['h'], 'none']))
        expected[case['id']] = valid
    require(any(expected.values()) and not all(expected.values()), 'positive and negative controls required')
    process = subprocess.run([str(circuit.resolve())], input='\n'.join(rows) + '\n', text=True,
                             capture_output=True, timeout=600)
    print(process.stdout, end='')
    print(process.stderr, end='')
    require(process.returncode == 0, 'compiled circuit process failed')
    observed = {}
    for line in process.stdout.splitlines():
        if line.startswith('case '):
            _, name, status = line.split()
            require(name not in observed and status in ('accepted', 'constraint_rejected'), 'duplicate/invalid C++ result')
            observed[name] = status == 'accepted'
    require(observed == expected, 'Sage/C++ composed-constraint mismatch: ' + ','.join(
        sorted(n for n in set(observed) | set(expected) if observed.get(n) != expected.get(n))))
    print(json.dumps({'model': 'PoSC (Proof of Signature Custody)', 'sage_python_cases': len(ids),
        'compiled_cases': len(expected), 'accepted': sum(expected.values()),
        'constraint_rejected': len(expected) - sum(expected.values()),
        'unrepresentable_mathematical_rows': unrepresentable, 'failed': 0,
        'coverage': 'actual composed assertions, no native preverification or fresh proof generation'}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', type=Path, default=ROOT / 'tests/quietproof/testdata/posc_sage_vectors.json')
    parser.add_argument('--circuit', type=Path, required=True)
    args = parser.parse_args()
    check(args.fixture, args.circuit)


if __name__ == '__main__':
    main()
