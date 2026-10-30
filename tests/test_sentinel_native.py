"""Independent finite-Q bridge controls; intake mocked, process/native dispatch denied.

Literal wire oracle frozen before native.py. These tests do not prove package
recovery, native execution, English truth or all66 planned controls.
"""
from copy import deepcopy
import base64
import gzip
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import sys
import unittest
from unittest.mock import Mock, patch
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'tests')]
from sentinel_v1 import native, native_build, native_runtime, refinement, challenges
from sentinel_v1.bindings import registry_root
from sentinel_v1.common import canonical, digest, identity, parse
from test_sentinel_challenges import packet

LITERAL = json.loads('{"actual_answer_hex_by_round":[["4b4e4f574e","434f4e464c494354"],["554e4b4e4f574e","434f4e464c494354"]],"actual_execution":"NOT_RUN","answer_receipts":[[{"answer_pin":{"bytes":5,"sha256":"04472bcb3649fa65cbe169a7966b6bbdadd645dc820bab126473d72171dcb879"},"context_admission_sha256":"d238a328efaf6be708a6ceb1e569546dc032a35728564a4e933fdd018aa7b8ba","graph_sha256":"84b7dcf7d9077e4ae1cf17b31e508469e95a139c9b29251295e4e87bdccf03ab","oracle_pin":{"bytes":166,"sha256":"ea7f6e4a37de89e7fba79a1ba30d1bf1513df3b9b13286b9b637e0550e8ce2a4"},"probe_id":"Q1","replay_sha256":"bf5fc0e723cd306f030497881134315f1be7f7e84b1c8e9f7235b65d21052977","round":1,"schema":"sentinel/native-answer-receipt/1"},{"answer_pin":{"bytes":8,"sha256":"d79910c78cef73436cb082e736cd62960bf56c2d8c6232362e6bde0eb62e33c9"},"context_admission_sha256":"d238a328efaf6be708a6ceb1e569546dc032a35728564a4e933fdd018aa7b8ba","graph_sha256":"84b7dcf7d9077e4ae1cf17b31e508469e95a139c9b29251295e4e87bdccf03ab","oracle_pin":{"bytes":166,"sha256":"b8eca681afa1319cbc779ac1eabed0fd4393d5cf70a909b9657a74c6c3e77a52"},"probe_id":"Q2","replay_sha256":"bf5fc0e723cd306f030497881134315f1be7f7e84b1c8e9f7235b65d21052977","round":1,"schema":"sentinel/native-answer-receipt/1"}],[{"answer_pin":{"bytes":7,"sha256":"23759997b3c59884dc4c0ff5320d6301b0e7f63bf0f6483a7b54d7d43bc5ccd1"},"context_admission_sha256":"7d46b49c62d82fbe1f891dd13ddd3465d3912cdca920f5e981010e484d927faa","graph_sha256":"7ca79d0e1300dbb9e8161e0baf21ac8a930b81b2ff24fe9a5720c687ee4d312d","oracle_pin":{"bytes":166,"sha256":"ea7f6e4a37de89e7fba79a1ba30d1bf1513df3b9b13286b9b637e0550e8ce2a4"},"probe_id":"Q1","replay_sha256":"827e285cd99a0208b960aea8c49c99abe196e0673b6fa6ab5ba962edeb8392fd","round":2,"schema":"sentinel/native-answer-receipt/1"},{"answer_pin":{"bytes":8,"sha256":"d79910c78cef73436cb082e736cd62960bf56c2d8c6232362e6bde0eb62e33c9"},"context_admission_sha256":"7d46b49c62d82fbe1f891dd13ddd3465d3912cdca920f5e981010e484d927faa","graph_sha256":"7ca79d0e1300dbb9e8161e0baf21ac8a930b81b2ff24fe9a5720c687ee4d312d","oracle_pin":{"bytes":166,"sha256":"b8eca681afa1319cbc779ac1eabed0fd4393d5cf70a909b9657a74c6c3e77a52"},"probe_id":"Q2","replay_sha256":"827e285cd99a0208b960aea8c49c99abe196e0673b6fa6ab5ba962edeb8392fd","round":2,"schema":"sentinel/native-answer-receipt/1"}]],"blockers_by_round":[["NO_BLOCKER","NO_BLOCKER"],["NO_BLOCKER","NO_BLOCKER"]],"candidate_sha256s":["84b7dcf7d9077e4ae1cf17b31e508469e95a139c9b29251295e4e87bdccf03ab","7ca79d0e1300dbb9e8161e0baf21ac8a930b81b2ff24fe9a5720c687ee4d312d"],"claim_ids":["C1","C2"],"context_flags_by_round":[[true,true],[true,true]],"documentary_by_round":[["NEITHER","BOTH"],["NEITHER","BOTH"]],"expected_answer_hex":["554e4b4e4f574e","434f4e464c494354"],"expected_final_output":{"accepted_current":2,"authority":0,"claims":2,"disposition":2,"exit":0,"matrix_nonzero":{"0":2,"1":1,"256":1,"257":1},"probes":2,"reason":0,"retained_events":1,"round":2,"scope":1,"session":1,"state":3},"expected_input":{"bytes":2077,"sha256":"099ff4529e23de5058f5e7241e882fc8c43851fe42fee4d17672d95ead48f7f4"},"expected_output":{"bytes":2725,"sha256":"57c701bca4362b64cda0797e416b8b1df10f6cb8d6589c3fd0b07d2412e4c50c"},"identity_digest_order":["e8c38aaa34e0c8f1fd4f27ed74534f23dec1a05424ed7acea1e38af2173c247a","618454885a8f48280831c20b65353a9936ccaa5cbd7a3920093400f144cc7e0e","6075baa56aa1e1aa49d997660420755f90db68cd9412c779cdda64dab8cd4af5","40752a711abee3233445d4940c8ac00c9d84db2b2db34cc61cec79cc68f2f740","d4fb8f53641c66fa3ebaafc124f2e7915bf7e131d594861c5709ceb73730ceab","73b72acd85a2260e7362213d6f77c437fc604aa4c7fb72dfa2328b28c64a9286","afd1d32f889ef6318e4d8bfaa20f8e9c2df5e8085fb993208b8994fde8b6569b","287ada4cf7ef37d6e76fa5071249829f43fe0959aab9787a44a4366a632989be","ec9f7ceec280189740d2334a9a7cd1d05b36ef174e557133dbd6213c63982104"],"links_by_claim":[{"anchor":"6075baa56aa1e1aa49d997660420755f90db68cd9412c779cdda64dab8cd4af5","first":0,"last":1,"representation":1},{"anchor":"6075baa56aa1e1aa49d997660420755f90db68cd9412c779cdda64dab8cd4af5","first":2,"last":3,"representation":1}],"oracle_set":{"rows":[{"oracle_pin":{"bytes":166,"sha256":"ea7f6e4a37de89e7fba79a1ba30d1bf1513df3b9b13286b9b637e0550e8ce2a4"},"probe_id":"Q1"},{"oracle_pin":{"bytes":166,"sha256":"b8eca681afa1319cbc779ac1eabed0fd4393d5cf70a909b9657a74c6c3e77a52"},"probe_id":"Q2"}],"schema":"sentinel/native-oracle-set/1"},"parentmask_hex":"80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","probe_ids":["Q1","Q2"],"public_provenance":"NOT_ESTABLISHED_BY_IR; separate full mock/actualsourcebound controls required","questions":{"rows":[{"claim_id":"C1","expected_answer_sha256":"23759997b3c59884dc4c0ff5320d6301b0e7f63bf0f6483a7b54d7d43bc5ccd1","input_sha256":"646e082a75c0bf17491cb68af357eee7be3838ae531f0e5d94b25d1f073a882b","ordinal":1,"probe_id":"Q1"},{"claim_id":"C2","expected_answer_sha256":"d79910c78cef73436cb082e736cd62960bf56c2d8c6232362e6bde0eb62e33c9","input_sha256":"71386ea1e76e555d8c2312af08361e420b140cf04b3dcda3f8ad84cca2b5ea8e","ordinal":2,"probe_id":"Q2"}],"schema":"sentinel/native-question-roster/1"},"reading":{"bytes":4,"sha256":"6075baa56aa1e1aa49d997660420755f90db68cd9412c779cdda64dab8cd4af5"},"reference_set":{"rows":[{"expected_answer_pin":{"bytes":7,"sha256":"23759997b3c59884dc4c0ff5320d6301b0e7f63bf0f6483a7b54d7d43bc5ccd1"},"probe_id":"Q1"},{"expected_answer_pin":{"bytes":8,"sha256":"d79910c78cef73436cb082e736cd62960bf56c2d8c6232362e6bde0eb62e33c9"},"probe_id":"Q2"}],"schema":"sentinel/native-reference-set/1"},"region":[0,3],"repair":{"from_graph_sha256":"84b7dcf7d9077e4ae1cf17b31e508469e95a139c9b29251295e4e87bdccf03ab","history_sha256":"218adcbc1e748f43fb1c4f71d763679cfc530c1d62406544eefd2c5f38e3b13b","prior_blocking_events":[{"context_admission_sha256":"d238a328efaf6be708a6ceb1e569546dc032a35728564a4e933fdd018aa7b8ba","kind":"MISMATCH_REFERENCE","probe_id":"Q1","replay_sha256":"bf5fc0e723cd306f030497881134315f1be7f7e84b1c8e9f7235b65d21052977","round":1}],"repair_parent_sha256s":["cf54c4364ab7eca5ec331feac9710d1b42046d10514c370670e5e19bcf0fca5b"],"schema":"sentinel/native-repair/1","to_graph_sha256":"7ca79d0e1300dbb9e8161e0baf21ac8a930b81b2ff24fe9a5720c687ee4d312d"},"role":"UNIT_PROJECTION_IR_ONLY_NEVER_PUBLIC_PROVENANCE_AUTHORITY","schema":"independent/bridge-projection-oracle/1","source":{"bytes":24,"sha256":"e8c38aaa34e0c8f1fd4f27ed74534f23dec1a05424ed7acea1e38af2173c247a"}}\n')

WIRE = bytes.fromhex("""
53544e31010000000100000154e8c38aaa34e0c8f1fd4f27ed74534f23dec1a05424ed7acea1e38af2173c247a618454885a
8f48280831c20b65353a9936ccaa5cbd7a3920093400f144cc7e0e6075baa56aa1e1aa49d997660420755f90db68cd9412c7
79cdda64dab8cd4af540752a711abee3233445d4940c8ac00c9d84db2b2db34cc61cec79cc68f2f740d4fb8f53641c66fa3e
baafc124f2e7915bf7e131d594861c5709ceb73730ceab73b72acd85a2260e7362213d6f77c437fc604aa4c7fb72dfa2328b
28c64a9286afd1d32f889ef6318e4d8bfaa20f8e9c2df5e8085fb993208b8994fde8b6569b287ada4cf7ef37d6e76fa50712
49829f43fe0959aab9787a44a4366a632989beec9f7ceec280189740d2334a9a7cd1d05b36ef174e557133dbd6213c639821
04000000180000000400000000000000030002000284b7dcf7d9077e4ae1cf17b31e508469e95a139c9b29251295e4e87bdc
cf03ab020000004400010001646e082a75c0bf17491cb68af357eee7be3838ae531f0e5d94b25d1f073a882b23759997b3c5
9884dc4c0ff5320d6301b0e7f63bf0f6483a7b54d7d43bc5ccd102000000440002000271386ea1e76e555d8c2312af08361e
420b140cf04b3dcda3f8ad84cca2b5ea8ed79910c78cef73436cb082e736cd62960bf56c2d8c6232362e6bde0eb62e33c903
0000002d00010301016075baa56aa1e1aa49d997660420755f90db68cd9412c779cdda64dab8cd4af5000000000000000103
0000002d00020201016075baa56aa1e1aa49d997660420755f90db68cd9412c779cdda64dab8cd4af5000000020000000304
00000132e8c38aaa34e0c8f1fd4f27ed74534f23dec1a05424ed7acea1e38af2173c247a618454885a8f48280831c20b6535
3a9936ccaa5cbd7a3920093400f144cc7e0e6075baa56aa1e1aa49d997660420755f90db68cd9412c779cdda64dab8cd4af5
40752a711abee3233445d4940c8ac00c9d84db2b2db34cc61cec79cc68f2f740d4fb8f53641c66fa3ebaafc124f2e7915bf7
e131d594861c5709ceb73730ceab73b72acd85a2260e7362213d6f77c437fc604aa4c7fb72dfa2328b28c64a9286afd1d32f
889ef6318e4d8bfaa20f8e9c2df5e8085fb993208b8994fde8b6569b287ada4cf7ef37d6e76fa5071249829f43fe0959aab9
787a44a4366a632989beec9f7ceec280189740d2334a9a7cd1d05b36ef174e557133dbd6213c639821040000001800000004
000000000000000301010500000063000184b7dcf7d9077e4ae1cf17b31e508469e95a139c9b29251295e4e87bdccf03ab04
472bcb3649fa65cbe169a7966b6bbdadd645dc820bab126473d72171dcb879479245f64032c883fcdf303aa9abd93efbd632
10a66027c3d7156433d13a5e29000500000063000284b7dcf7d9077e4ae1cf17b31e508469e95a139c9b29251295e4e87bdc
cf03abd79910c78cef73436cb082e736cd62960bf56c2d8c6232362e6bde0eb62e33c907cf6849fd58842b80b1b23c6afdc9
717861a9a1738f2b8048c4cbb4f247787d00070000000006000001407ca79d0e1300dbb9e8161e0baf21ac8a930b81b2ff24
fe9a5720c687ee4d312d2cbc6b06c71512e422becc98ae1323d2ef3330a4ae472996ad3d552cf1f589a68000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300
00002d00010301016075baa56aa1e1aa49d997660420755f90db68cd9412c779cdda64dab8cd4af500000000000000010300
00002d00020201016075baa56aa1e1aa49d997660420755f90db68cd9412c779cdda64dab8cd4af500000002000000030400
000132e8c38aaa34e0c8f1fd4f27ed74534f23dec1a05424ed7acea1e38af2173c247a618454885a8f48280831c20b65353a
9936ccaa5cbd7a3920093400f144cc7e0e6075baa56aa1e1aa49d997660420755f90db68cd9412c779cdda64dab8cd4af540
752a711abee3233445d4940c8ac00c9d84db2b2db34cc61cec79cc68f2f740d4fb8f53641c66fa3ebaafc124f2e7915bf7e1
31d594861c5709ceb73730ceab73b72acd85a2260e7362213d6f77c437fc604aa4c7fb72dfa2328b28c64a9286afd1d32f88
9ef6318e4d8bfaa20f8e9c2df5e8085fb993208b8994fde8b6569b287ada4cf7ef37d6e76fa5071249829f43fe0959aab978
7a44a4366a632989beec9f7ceec280189740d2334a9a7cd1d05b36ef174e557133dbd6213c63982104000000180000000400
000000000000030101050000006300017ca79d0e1300dbb9e8161e0baf21ac8a930b81b2ff24fe9a5720c687ee4d312d2375
9997b3c59884dc4c0ff5320d6301b0e7f63bf0f6483a7b54d7d43bc5ccd16b25301355cfa7fbdbb8d8e37a98646b6657c1e1
57ab9c18a754c6b8095580e800050000006300027ca79d0e1300dbb9e8161e0baf21ac8a930b81b2ff24fe9a5720c687ee4d
312dd79910c78cef73436cb082e736cd62960bf56c2d8c6232362e6bde0eb62e33c903da04d506bf52e98a8cef43322c62db
dff7b0fa1d71a5064f7ffe2b371fe38f0007000000000800000000
""")

OUTPUT = bytes.fromhex("""
5354523101020000e8c38aaa34e0c8f1fd4f27ed74534f23dec1a05424ed7acea1e38af2173c247a618454885a8f48280831
c20b65353a9936ccaa5cbd7a3920093400f144cc7e0e6075baa56aa1e1aa49d997660420755f90db68cd9412c779cdda64da
b8cd4af540752a711abee3233445d4940c8ac00c9d84db2b2db34cc61cec79cc68f2f740d4fb8f53641c66fa3ebaafc124f2
e7915bf7e131d594861c5709ceb73730ceab73b72acd85a2260e7362213d6f77c437fc604aa4c7fb72dfa2328b28c64a9286
afd1d32f889ef6318e4d8bfaa20f8e9c2df5e8085fb993208b8994fde8b6569b287ada4cf7ef37d6e76fa5071249829f43fe
0959aab9787a44a4366a632989beec9f7ceec280189740d2334a9a7cd1d05b36ef174e557133dbd6213c6398210400000018
0000000400000000000000037ca79d0e1300dbb9e8161e0baf21ac8a930b81b2ff24fe9a5720c687ee4d312d020002000200
0200010001030103020303030303030303030303030303030303030303030303030303030303030303030303030303030303
0303030303030303030303030303030303030303038000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000201000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000101000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
00000000000000000000000000000000000000000000000000
""")


def projection():
    value = LITERAL
    rounds = []
    for index in range(2):
        claims = [{'id': name, 'documentary': value['documentary_by_round'][index][ordinal],
                   'links': [value['links_by_claim'][ordinal]]}
                  for ordinal, name in enumerate(value['claim_ids'])]
        answers = [{'actual': digest(bytes.fromhex(value['actual_answer_hex_by_round'][index][ordinal])),
                    'receipt': digest(canonical(value['answer_receipts'][index][ordinal])),
                    'blocker': value['blockers_by_round'][index][ordinal]}
                   for ordinal in range(2)]
        rounds.append({'candidate': value['candidate_sha256s'][index], 'claims': claims,
            'context': True, 'adjudication': True, 'answers': answers,
            'repair': None if index == 0 else value['repair'],
            'prior_events': [] if index == 0 else value['repair']['prior_blocking_events']})
    return {'hashes': value['identity_digest_order'], 'source_bytes': value['source']['bytes'],
        'reading_bytes': value['reading']['bytes'], 'region': value['region'],
        'claim_ids': value['claim_ids'], 'probe_ids': value['probe_ids'],
        'questions': value['questions'], 'rounds': rounds}


def put(registry, raw):
    registry[digest(raw)] = raw
    return digest(raw)


def evidence(registry):
    manifest_raw = (ROOT / 'qualification/v2/manifest.json').read_bytes()
    archive = json.loads(gzip.decompress((ROOT / 'qualification/v2/evidence.json.gz').read_bytes()))
    values = {name: base64.b64decode(value, validate=True) for name, value in archive['items'].items()}
    for name in ('pure-receipt.json', 'pure-result.json', 'pure-review.json',
                 'wire-receipt.json', 'wire-result.json', 'wire-review.json'):
        put(registry, values[name])
    manifest_key = put(registry, manifest_raw)
    evaluator = canonical(native.evaluator_sources())
    put(registry, evaluator)
    return manifest_key, json.loads(manifest_raw), values, evaluator


def source_fixture(answer=b'MATERIAL_CHANGE'):
    value, registry, admission, locator = packet()
    graph = parse(registry[value['graph_sha256']])
    source = graph['source_set'][0]
    source['representation'].update(kind='DERIVED_UTF8', record_sha256=digest(b'mocked reading record'))
    locator.update({key: deepcopy(source[key]) for key in ('source', 'representation', 'revision')})
    locator['selector']['kind'] = 'DERIVED_UTF8'
    locator_raw = canonical(locator); target = put(registry, locator_raw)
    value['graph_sha256'] = put(registry, canonical(graph))
    value['source_set_sha256'] = put(registry, canonical(graph['source_set']))
    value['probes'][0]['target_locator_sha256'] = target
    oracle = parse(registry[value['probes'][0]['oracle_pin']['sha256']])
    oracle['source_set_sha256'] = value['source_set_sha256']
    oracle_raw = canonical(oracle); put(registry, oracle_raw)
    value['probes'][0]['oracle_pin'] = identity(oracle_raw)
    admission.update(graph_sha256=value['graph_sha256'], source_set_sha256=value['source_set_sha256'],
                     oracles={'Q1': digest(oracle_raw)})
    raw, authority = canonical(value), canonical(admission)
    put(registry, raw); put(registry, authority)
    put(registry, answer)
    replay = challenges.replay(raw, digest(raw), registry, registry_root(registry),
                               authority, digest(authority), {'Q1': answer})
    put(registry, replay)
    history_raw = refinement.advance(None, None, raw, digest(raw), registry,
        registry_root(registry), authority, digest(authority), {'Q1': answer}, [])
    history_key = put(registry, history_raw)
    history = parse(history_raw)
    target_bytes = registry[value['probes'][0]['transformation']['before_pin']['sha256']]
    resolution = {'status': 'RESOLVED_BYTES', 'gaps': [], 'parts': [{'span': [0, len(target_bytes)],
        'data': target_bytes, 'sha256': digest(target_bytes)}], 'locator_sha256': target,
        'dependency_locator_sha256s': [], 'source': deepcopy(source['source']),
        'package_id': source['source']['package_id'], 'revision': deepcopy(source['revision']),
        'representation': deepcopy(source['representation']), 'coordinate_kind': 'DERIVED_UTF8_BYTE'}
    return value, registry, history, history_key, locator_raw, resolution


def public_fixture(answer=b'MATERIAL_CHANGE'):
    value, registry, history, history_key, locator_raw, resolution = source_fixture(answer)
    target = digest(locator_raw)
    manifest_key, manifest, retained, evaluator = evidence(registry)
    provenance = b'Manual independent development fixture; no external authentication.'
    put(registry, provenance)
    context = {'schema': 'sentinel/native-context-admission/1',
        'graph_sha256': value['graph_sha256'], 'source_set_sha256': value['source_set_sha256'],
        'test_contract_sha256': history['test_contract_sha256'], 'source_locator_sha256': target,
        'context_complete': True, 'adjudication_complete': True, 'blockers': {'Q1': 'NO_BLOCKER'},
        'provenance_pin': identity(provenance)}
    context_key = put(registry, canonical(context)); row = history['rounds'][0]
    wire_result = json.loads(retained['wire-result.json'])['worker']['binary']
    oracle = parse(registry[value['probes'][0]['oracle_pin']['sha256']])
    oracle_set = {'schema': 'sentinel/native-oracle-set/1', 'rows': [
        {'probe_id': 'Q1', 'oracle_pin': value['probes'][0]['oracle_pin']}]}
    reference = {'schema': 'sentinel/native-reference-set/1', 'rows': [
        {'probe_id': 'Q1', 'expected_answer_pin': oracle['answer_pin']}]}
    admitted = {'ordinal': 1, 'graph_sha256': row['graph_sha256'],
        'challenge_set_sha256': row['challenge_set_sha256'],
        'challenge_admission_sha256': row['admission_sha256'], 'replay_sha256': row['replay_sha256'],
        'context_admission_sha256': context_key}
    gate = {'schema': 'sentinel/native-gate-admission/1', 'profile': native.PROFILE,
        'source_set_sha256': value['source_set_sha256'], 'test_contract_sha256': history['test_contract_sha256'],
        'source_locator_sha256': target, 'mandatory_claim_ids': ['C1'], 'mandatory_probe_ids': ['Q1'],
        'rounds': [admitted], 'versioned_manifest_sha256': manifest_key,
        'native_binary_pin': {'bytes': wire_result['file_bytes'], 'sha256': wire_result['sha256']},
        'pure_receipt_pin': manifest['evidence']['pure-receipt.json'],
        'wire_receipt_pin': manifest['evidence']['wire-receipt.json'],
        'evaluator_manifest_pin': identity(evaluator), 'oracle_set_sha256': digest(canonical(oracle_set)),
        'reference_set_sha256': digest(canonical(reference)), 'provenance_pin': identity(provenance)}
    return {'registry': registry, 'history': history, 'history_key': history_key, 'gate': gate,
        'context': context, 'locator_raw': locator_raw, 'resolution': resolution}


def request_args(fixture):
    registry = dict(fixture['registry']); gate = deepcopy(fixture['gate'])
    gate_key = put(registry, canonical(gate)); target = digest(fixture['locator_raw'])
    locators = {target: fixture['locator_raw']}; revisions = {}
    root = registry_root(registry)
    request = {'schema': 'sentinel/native-request/1', 'profile': native.PROFILE,
        'history_sha256': fixture['history_key'], 'gate_admission_sha256': gate_key,
        'source_locator_sha256': target, 'registry_sha256': root,
        'locator_registry_sha256': registry_root(locators), 'revision_registry_sha256': registry_root(revisions)}
    raw = canonical(request)
    return (raw, digest(raw), registry, root, Path('/manual/fixture.zip'), Path('/manual/share.txt'),
        locators, registry_root(locators), revisions, registry_root(revisions))


def fixture_rows(fixture, value, admission, answers, previous=None):
    registry = fixture['registry']
    for answer in answers.values(): put(registry, answer)
    raw, authority = canonical(value), canonical(admission)
    put(registry, raw); put(registry, authority)
    replay = challenges.replay(raw, digest(raw), registry, registry_root(registry),
                               authority, digest(authority), answers)
    put(registry, replay)
    history = refinement.advance(previous, None if previous is None else digest(previous),
        raw, digest(raw), registry, registry_root(registry), authority, digest(authority),
        answers, [] if previous is None else ['C1'])
    put(registry, history)
    return history


def multi_fixture():
    fixture = public_fixture(); registry = fixture['registry']
    old = fixture['history']['rounds'][0]
    value = parse(registry[old['challenge_set_sha256']])
    admission = parse(registry[old['admission_sha256']])
    graph = parse(registry[value['graph_sha256']])
    extra = deepcopy(graph['nodes'][0]); extra['id'] = 'C2'
    graph['nodes'].append(extra)
    value['graph_sha256'] = put(registry, canonical(graph))
    admission['graph_sha256'] = value['graph_sha256']
    probe = deepcopy(value['probes'][0]); probe.update(id='Q2', claim_id='C2')
    oracle = parse(registry[probe['oracle_pin']['sha256']]); oracle['probe_id'] = 'Q2'
    probe['oracle_pin'] = identity(canonical(oracle)); put(registry, canonical(oracle))
    value['probes'].append(probe); admission['oracles']['Q2'] = probe['oracle_pin']['sha256']
    first = fixture_rows(fixture, value, admission, {'Q1': b'WRONG', 'Q2': b'MATERIAL_CHANGE'})
    graph['nodes'][0]['text'] = 'All controllers retain the stated maintenance exception.'
    value['graph_sha256'] = put(registry, canonical(graph)); admission['graph_sha256'] = value['graph_sha256']
    last = fixture_rows(fixture, value, admission,
                        {'Q1': b'MATERIAL_CHANGE', 'Q2': b'MATERIAL_CHANGE'}, first)
    fixture['history'] = parse(last); fixture['history_key'] = digest(last)
    fixture['gate'].update(test_contract_sha256=fixture['history']['test_contract_sha256'],
        mandatory_claim_ids=['C1', 'C2'], mandatory_probe_ids=['Q1', 'Q2'])
    oracle_rows, reference_rows, admitted = [], [], []
    for probe in value['probes']:
        oracle = parse(registry[probe['oracle_pin']['sha256']])
        oracle_rows.append({'probe_id': probe['id'], 'oracle_pin': probe['oracle_pin']})
        reference_rows.append({'probe_id': probe['id'], 'expected_answer_pin': oracle['answer_pin']})
    fixture['gate']['oracle_set_sha256'] = digest(canonical({'schema': 'sentinel/native-oracle-set/1', 'rows': oracle_rows}))
    fixture['gate']['reference_set_sha256'] = digest(canonical({'schema': 'sentinel/native-reference-set/1', 'rows': reference_rows}))
    for row in fixture['history']['rounds']:
        context = deepcopy(fixture['context'])
        context.update(graph_sha256=row['graph_sha256'], blockers={'Q1': 'NO_BLOCKER', 'Q2': 'NO_BLOCKER'},
                       test_contract_sha256=fixture['history']['test_contract_sha256'])
        context_key = put(registry, canonical(context))
        admitted.append({'ordinal': row['ordinal'], 'graph_sha256': row['graph_sha256'],
            'challenge_set_sha256': row['challenge_set_sha256'], 'challenge_admission_sha256': row['admission_sha256'],
            'replay_sha256': row['replay_sha256'], 'context_admission_sha256': context_key})
    fixture['gate']['rounds'] = admitted
    return fixture


def changed_history(fixture, history, prefix=False):
    if prefix:
        previous = parse(fixture['registry'][history['predecessor_sha256']])
        previous['rounds'] = deepcopy(history['rounds'][:-1])
        history['predecessor_sha256'] = put(fixture['registry'], canonical(previous))
    fixture['history'] = history
    fixture['history_key'] = put(fixture['registry'], canonical(history))


def bind_history(fixture, history_raw, value):
    registry = fixture['registry']; history = parse(history_raw)
    fixture['history'] = history; fixture['history_key'] = put(registry, history_raw)
    fixture['gate'].update(source_set_sha256=value['source_set_sha256'],
                          test_contract_sha256=history['test_contract_sha256'])
    oracles, references, admitted = [], [], []
    for probe in value['probes']:
        if probe['oracle_pin'] is not None:
            oracle = parse(registry[probe['oracle_pin']['sha256']])
            oracles.append({'probe_id': probe['id'], 'oracle_pin': probe['oracle_pin']})
            references.append({'probe_id': probe['id'], 'expected_answer_pin': oracle['answer_pin']})
    fixture['gate']['oracle_set_sha256'] = digest(canonical({'schema': 'sentinel/native-oracle-set/1', 'rows': oracles}))
    fixture['gate']['reference_set_sha256'] = digest(canonical({'schema': 'sentinel/native-reference-set/1', 'rows': references}))
    for row in history['rounds']:
        context = deepcopy(fixture['context'])
        context.update(graph_sha256=row['graph_sha256'], source_set_sha256=value['source_set_sha256'],
            test_contract_sha256=history['test_contract_sha256'],
            blockers={probe['id']: 'NO_BLOCKER' for probe in value['probes']})
        key = put(registry, canonical(context))
        admitted.append({'ordinal': row['ordinal'], 'graph_sha256': row['graph_sha256'],
            'challenge_set_sha256': row['challenge_set_sha256'], 'challenge_admission_sha256': row['admission_sha256'],
            'replay_sha256': row['replay_sha256'], 'context_admission_sha256': key})
    fixture['gate']['rounds'] = admitted


def rebuild_single(fixture, graph=None, transform=None):
    registry = fixture['registry']; row = fixture['history']['rounds'][-1]
    value = parse(registry[row['challenge_set_sha256']]); admission = parse(registry[row['admission_sha256']])
    if graph is not None:
        value['graph_sha256'] = put(registry, canonical(graph))
        value['source_set_sha256'] = put(registry, canonical(graph['source_set']))
    admission.update(graph_sha256=value['graph_sha256'], source_set_sha256=value['source_set_sha256'])
    for probe in value['probes']:
        if probe['oracle_pin'] is not None:
            oracle = parse(registry[probe['oracle_pin']['sha256']])
            oracle['source_set_sha256'] = value['source_set_sha256']
            key = put(registry, canonical(oracle)); probe['oracle_pin'] = identity(registry[key])
            admission['oracles'][probe['id']] = key
    if transform is not None: transform(value, admission)
    answers = {probe['id']: b'MATERIAL_CHANGE' for probe in value['probes']}
    history = fixture_rows(fixture, value, admission, answers)
    bind_history(fixture, history, value)
    return fixture


def rewritten_first_round(fixture, history, change):
    registry = fixture['registry']; row = history['rounds'][0]
    value = parse(registry[row['challenge_set_sha256']])
    admission = parse(registry[row['admission_sha256']])
    if change == 'Q': value['probes'].reverse()
    else:
        probe = value['probes'][0]; oracle = parse(registry[probe['oracle_pin']['sha256']])
        put(registry, b'OTHER_EXPECTED'); oracle['answer_pin'] = identity(b'OTHER_EXPECTED')
        key = put(registry, canonical(oracle)); probe['oracle_pin'] = identity(registry[key])
        admission['oracles'][probe['id']] = key
    raw, authority = canonical(value), canonical(admission)
    replay = challenges.replay(raw, digest(raw), registry, registry_root(registry),
        authority, digest(authority), {'Q1': b'WRONG', 'Q2': b'MATERIAL_CHANGE'})
    row.update(challenge_set_sha256=put(registry, raw), admission_sha256=put(registry, authority),
               replay_sha256=put(registry, replay), results=parse(replay)['results'])
    row['counterexamples'] = refinement.failures(parse(replay), row['graph_sha256'])
    history['rounds'][1]['repair_parent_sha256s'] = [r['sha256'] for r in row['counterexamples']]
    fixture['gate']['rounds'][0].update(challenge_set_sha256=row['challenge_set_sha256'],
        challenge_admission_sha256=row['admission_sha256'], replay_sha256=row['replay_sha256'])


class NativeBridgeControls(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        patch.object(subprocess, 'Popen', side_effect=AssertionError('real process/native forbidden')).start()
        patch.object(os, 'execv', side_effect=AssertionError('exec forbidden')).start()

    def prepare(self, fixture):
        with patch.object(native, 'resolve_locator', return_value=fixture['resolution']):
            return native.prepare_request(*request_args(fixture))

    def test_literal_two_claim_two_probe_two_round_encoding(self):
        self.assertEqual(digest(WIRE), '099ff4529e23de5058f5e7241e882fc8c43851fe42fee4d17672d95ead48f7f4')
        self.assertEqual(native.encode_projection(projection()), WIRE)

    def test_literal_qualified_response_retains_old_failure(self):
        result = native.parse_response(OUTPUT, b'', 0, projection())
        self.assertEqual(result['status'], 'NATIVE_QUALIFIED_FOR_FINITE_Q')
        self.assertEqual(result['execution_authority'], 'NONE')
        self.assertEqual(bytes.fromhex(result['failure_mask_hex']), b'\x80' + bytes(255))
        self.assertEqual(result['semantic_completeness'], 'UNPROVEN')

    def test_identity_echo_each_of_nine_and_counters_refuse(self):
        for offset in [8 + 32 * index for index in range(9)] + [296, 300, 304, 308, 312, 344, 345, 347, 349]:
            raw = bytearray(OUTPUT); raw[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                native.parse_response(bytes(raw), b'', 0, projection())

    def test_response_truncation_trailing_stderr_exit_authority_refuse(self):
        for raw, stderr, code in [(OUTPUT[:-1], b'', 0), (OUTPUT + b'X', b'', 0),
                                  (OUTPUT, b'warning', 0), (OUTPUT, b'', 2), (b'', b'', 0)]:
            with self.subTest(length=len(raw), stderr=stderr, code=code), self.assertRaises(ValueError):
                native.parse_response(raw, stderr, code, projection())
        for offset in (0, 4, 5, 6, 353, 354, 355, 356):
            raw = bytearray(OUTPUT); raw[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                native.parse_response(bytes(raw), b'', 0, projection())

    def test_response_documentary_mask_matrix_and_unused_slots_refuse(self):
        for offset in (357, 359, 420, 421, 452, 676, 677, 678, 933, 934, 2724):
            raw = bytearray(OUTPUT); raw[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                native.parse_response(bytes(raw), b'', 0, projection())

    def test_projection_typed_flags_roster_and_link_bounds_refuse(self):
        mutations = [lambda p: p['rounds'][0].update(context=1),
            lambda p: p['questions']['rows'][0].update(ordinal=True),
            lambda p: p['rounds'][0]['claims'][0]['links'][0].update(first=False),
            lambda p: p.update(region=[0, 65537]), lambda p: p.update(probe_ids=['Q1', 'Q1']),
            lambda p: p['rounds'][0].update(claims=[]), lambda p: p['rounds'][0].update(answers=[])]
        for change in mutations:
            value = deepcopy(projection()); change(value)
            with self.assertRaises(ValueError): native.encode_projection(value)

    def test_false_context_is_encoded_not_upgraded_or_inferred(self):
        value = deepcopy(projection()); value['rounds'][0]['context'] = False
        wire = native.encode_projection(value)
        self.assertNotEqual(wire, WIRE)
        self.assertIn(native._identity_wire(value) + b'\x00\x01', wire)

    def test_blocker_events_keep_two_records_but_one_mask_bit(self):
        value = deepcopy(projection())
        event = dict(value['rounds'][1]['prior_events'][0], kind='REQUIRED_CONFLICT')
        value['rounds'][1]['prior_events'].append(event)
        self.assertEqual(native._mask(value['rounds'][1]['prior_events'], value['probe_ids']),
                         b'\x80' + bytes(255))
        self.assertEqual(len(value['rounds'][1]['prior_events']), 2)

    def test_public_positive_uses_real_replay_and_held_evidence_intake_mocked(self):
        fixture = public_fixture(); wire, prepared = self.prepare(fixture)
        self.assertTrue(wire.startswith(b'STN1\x01'))
        self.assertEqual(prepared['status'], 'PREPARED_UNQUALIFIED')
        self.assertEqual(prepared['execution_authority'], 'NONE')
        self.assertEqual(prepared['projection']['claim_ids'], ['C1'])
        self.assertEqual(prepared['projection']['probe_ids'], ['Q1'])

    def test_public_wrong_request_pin_and_registry_roots_refuse(self):
        fixture = public_fixture(); self.prepare(fixture); args = list(request_args(fixture))
        for index, replacement in ((1, '0' * 64), (3, '0' * 64), (7, '0' * 64), (9, '0' * 64)):
            altered = list(args); altered[index] = replacement
            with patch.object(native, 'resolve_locator') as intake, self.subTest(index=index), \
                 self.assertRaises(ValueError): native.prepare_request(*altered)
            intake.assert_not_called()

    def test_public_source_reading_meta_gaps_parts_and_quote_refuse(self):
        for change in ('source', 'reading', 'metadata', 'original', 'gap', 'parts', 'quote'):
            fixture = public_fixture(); self.prepare(fixture); resolution = fixture['resolution']
            if change == 'source': resolution['source']['sha256'] = '0' * 64
            elif change == 'reading': resolution['representation']['sha256'] = '0' * 64
            elif change == 'metadata': resolution['representation']['record_sha256'] = '0' * 64
            elif change == 'original': resolution['representation']['kind'] = 'ORIGINAL'
            elif change == 'gap': resolution['gaps'] = [[1, 2]]
            elif change == 'parts': resolution['parts'].append(deepcopy(resolution['parts'][0]))
            else: resolution['parts'][0]['data'] = b'wrong bytes'
            with self.subTest(change=change), self.assertRaises(ValueError): self.prepare(fixture)

    def test_public_missing_claim_probe_oracle_reference_scope_refuse(self):
        for key, value in [('mandatory_claim_ids', ['MISSING']), ('mandatory_probe_ids', ['MISSING']),
            ('oracle_set_sha256', '0' * 64), ('reference_set_sha256', '0' * 64),
            ('source_set_sha256', '0' * 64), ('test_contract_sha256', '0' * 64)]:
            fixture = public_fixture(); self.prepare(fixture); fixture['gate'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.prepare(fixture)

    def test_public_missing_answer_checker_history_and_evaluator_refuse(self):
        for change in ('answer', 'checker', 'history', 'evaluator', 'wirepin', 'version'):
            fixture = public_fixture(); self.prepare(fixture)
            if change == 'answer': fixture['registry'].pop(digest(b'MATERIAL_CHANGE'))
            elif change == 'checker': fixture['registry'].pop(challenges.SOURCE_EPOCH)
            elif change == 'history': fixture['registry'].pop(fixture['history_key'])
            elif change == 'evaluator': fixture['gate']['evaluator_manifest_pin'] = identity(b'missing')
            elif change == 'wirepin': fixture['gate']['native_binary_pin']['sha256'] = '0' * 64
            else: fixture['gate']['versioned_manifest_sha256'] = '0' * 64
            with self.subTest(change=change), self.assertRaises(ValueError): self.prepare(fixture)

    def test_public_missing_or_mistyped_context_is_not_a_true_default(self):
        for change in ('missing', 'integer', 'blocker_subset'):
            fixture = public_fixture(); self.prepare(fixture); context = fixture['context']
            if change == 'missing': context.pop('context_complete')
            elif change == 'integer': context['context_complete'] = 1
            else: context['blockers'] = {}
            context_key = put(fixture['registry'], canonical(context))
            fixture['gate']['rounds'][0]['context_admission_sha256'] = context_key
            with self.subTest(change=change), self.assertRaises(ValueError): self.prepare(fixture)

    def test_public_false_context_and_nonzero_blocker_are_encoded(self):
        for field, value in [('context_complete', False), ('adjudication_complete', False),
                             ('blockers', {'Q1': 'REQUIRED_UNRESOLVED'})]:
            fixture = public_fixture(); fixture['context'][field] = value
            key = put(fixture['registry'], canonical(fixture['context']))
            fixture['gate']['rounds'][0]['context_admission_sha256'] = key
            _wire, prepared = self.prepare(fixture)
            row = prepared['projection']['rounds'][0]
            if field == 'blockers': self.assertEqual(row['answers'][0]['blocker'], 'REQUIRED_UNRESOLVED')
            else: self.assertFalse(row['context' if field == 'context_complete' else 'adjudication'])


    def test_public_mismatch_keeps_actual_digest_for_native_decision(self):
        fixture = public_fixture(b'WRONG'); _wire, prepared = self.prepare(fixture)
        self.assertEqual(prepared['projection']['rounds'][0]['answers'][0]['actual'], digest(b'WRONG'))
        expected = prepared['projection']['questions']['rows'][0]['expected_answer_sha256']
        self.assertNotEqual(expected, digest(b'WRONG'))
        self.assertEqual(prepared['status'], 'PREPARED_UNQUALIFIED')

    def test_public_missing_actual_retains_expected_reference_and_refuses(self):
        fixture = public_fixture(b'WRONG'); self.prepare(fixture)
        self.assertIn(digest(b'MATERIAL_CHANGE'), fixture['registry'])
        fixture['registry'].pop(digest(b'WRONG'))
        with self.assertRaises(ValueError): self.prepare(fixture)

    def test_public_selfconsistent_forged_answer_summary_refuses_replay(self):
        fixture = public_fixture(); self.prepare(fixture)
        history = deepcopy(fixture['history']); row = history['rounds'][0]
        replay = parse(fixture['registry'][row['replay_sha256']])
        put(fixture['registry'], b'WRONG')
        replay['results'][0]['answer_pin'] = identity(b'WRONG')
        row['results'] = replay['results']
        row['replay_sha256'] = put(fixture['registry'], canonical(replay))
        fixture['history_key'] = put(fixture['registry'], canonical(history))
        fixture['gate']['rounds'][0]['replay_sha256'] = row['replay_sha256']
        with self.assertRaisesRegex(ValueError, 'historical result'):
            self.prepare(fixture)

    def test_public_closed_gate_and_missing_context_refuse(self):
        for change in ('unknown', 'context'):
            fixture = public_fixture(); self.prepare(fixture)
            if change == 'unknown': fixture['gate']['accepted'] = True
            else:
                key = fixture['gate']['rounds'][0]['context_admission_sha256']
                fixture['registry'].pop(key)
            with self.subTest(change=change), self.assertRaises(ValueError): self.prepare(fixture)

    def test_prepare_memory_error_is_explicit_refusal(self):
        with patch.object(native, '_prepare_request', side_effect=MemoryError):
            with self.assertRaisesRegex(ValueError, 'MemoryError'):
                native.prepare_request(*([None] * 10))


    def test_public_two_claim_two_probe_two_round_positive_retains_failure(self):
        fixture = multi_fixture(); _wire, prepared = self.prepare(fixture)
        p = prepared['projection']
        self.assertEqual(p['claim_ids'], ['C1', 'C2'])
        self.assertEqual(p['probe_ids'], ['Q1', 'Q2'])
        self.assertEqual(len(p['rounds']), 2)
        self.assertEqual(p['rounds'][0]['answers'][0]['actual'], digest(b'WRONG'))
        self.assertEqual(p['rounds'][1]['answers'][0]['actual'], digest(b'MATERIAL_CHANGE'))
        self.assertEqual(len(p['rounds'][1]['repair']['repair_parent_sha256s']), 1)
        self.assertEqual(native._mask(p['rounds'][1]['prior_events'], p['probe_ids']), b'\x80' + bytes(255))


    def test_R3_R7_closed_request_gate_and_profile(self):
        for change in ('missing_gate', 'gate_pin', 'request_field', 'profile'):
            fixture = public_fixture(); self.prepare(fixture); args = list(request_args(fixture))
            request = parse(args[0]); registry = dict(args[2]); key = request['gate_admission_sha256']
            if change == 'missing_gate': registry.pop(key)
            elif change == 'gate_pin': registry[key] = canonical(dict(fixture['gate'], profile='wrong'))
            elif change == 'request_field': request['accepted'] = True
            else: request['profile'] = 'WRONG_PROFILE'
            root = digest(canonical({key: identity(raw) for key, raw in registry.items()}))
            request['registry_sha256'] = root
            args[0] = canonical(request); args[1] = digest(args[0]); args[2:4] = [registry, root]
            with patch.object(native, 'resolve_locator', return_value=fixture['resolution']), self.subTest(change=change):
                with self.assertRaises(ValueError): native.prepare_request(*args)

    def test_R9_R17_missing_reading_and_boolean_span(self):
        for change in ('reading', 'bool_start'):
            fixture = public_fixture(); self.prepare(fixture)
            if change == 'reading': fixture['resolution']['representation'].pop('record_sha256')
            else: fixture['resolution']['parts'][0]['span'][0] = False
            with self.subTest(change=change), self.assertRaises(ValueError): self.prepare(fixture)

    def test_R10_multiple_sources_even_when_complete_and_bound_refuse(self):
        fixture = multi_fixture(); self.prepare(fixture)
        graph = parse(fixture['registry'][fixture['history']['rounds'][0]['graph_sha256']])
        extra = deepcopy(graph['source_set'][0]); extra['id'] = 'S2'; graph['source_set'].append(extra)
        graph['nodes'][-1]['evidence'][0]['source_id'] = 'S2'
        rebuild_single(fixture, graph)
        with self.assertRaisesRegex(ValueError, 'multi-source'): self.prepare(fixture)

    def test_R19_R20_R22_complete_ordered_claim_and_probe_rosters(self):
        for change in ('extra_claim', 'reorder_claims', 'reorder_Q', 'subset_Q'):
            fixture = multi_fixture(); self.prepare(fixture)
            if change == 'extra_claim': fixture['gate']['mandatory_claim_ids'] = ['C1']
            elif change == 'reorder_claims': fixture['gate']['mandatory_claim_ids'].reverse()
            elif change == 'reorder_Q': fixture['gate']['mandatory_probe_ids'].reverse()
            else: fixture['gate']['mandatory_probe_ids'] = ['Q1']
            with self.subTest(change=change), self.assertRaises(ValueError): self.prepare(fixture)

    def test_R23_R24_probe_subject_and_claim_without_probe(self):
        for change in ('zero', 'not_mandatory', 'untested'):
            fixture = multi_fixture(); self.prepare(fixture)
            def alter(value, admission):
                value['probes'][0]['claim_id'] = 0 if change == 'zero' else ('MISSING' if change == 'not_mandatory' else 'C2')
            with self.subTest(change=change), self.assertRaises(ValueError):
                rebuild_single(fixture, transform=alter); self.prepare(fixture)

    def test_R25_R26_missing_oracle_and_unresolved_oracle(self):
        for change in ('missing', 'unresolved'):
            fixture = public_fixture(); self.prepare(fixture)
            row = fixture['history']['rounds'][0]
            value = parse(fixture['registry'][row['challenge_set_sha256']])
            if change == 'missing': fixture['registry'].pop(value['probes'][0]['oracle_pin']['sha256'])
            else:
                def alter(value, admission):
                    value['probes'][0]['oracle_pin'] = None; admission['oracles'] = {}
                rebuild_single(fixture, transform=alter)
            with self.subTest(change=change), self.assertRaises(ValueError): self.prepare(fixture)

    def test_R29_R30_R31_R39_historical_impact_Q_oracle_and_parents(self):
        for change in ('impact', 'Q', 'oracle', 'parents'):
            fixture = multi_fixture(); self.prepare(fixture); history = deepcopy(fixture['history'])
            if change == 'impact': history['rounds'][1].update(changed_nodes=[], invalidated_nodes=[])
            elif change == 'parents': history['rounds'][1]['repair_parent_sha256s'] = []
            else:
                rewritten_first_round(fixture, history, change)
            changed_history(fixture, history, prefix=change in ('Q', 'oracle'))
            with self.subTest(change=change), self.assertRaises(ValueError): self.prepare(fixture)

    def test_R36_R37_R38_historical_mismatch_blocker_and_future_mask(self):
        for change in ('missing_mismatch', 'missing_blocker', 'future'):
            value = deepcopy(projection()); raw = bytearray(OUTPUT)
            if change == 'missing_mismatch': raw[421] = 0; raw[351:353] = bytes(2)
            elif change == 'missing_blocker': value['rounds'][0]['answers'][1]['blocker'] = 'REQUIRED_CONFLICT'
            else: raw[421 + 64] = 128; raw[351:353] = (2).to_bytes(2, 'big')
            with self.subTest(change=change), self.assertRaises(ValueError):
                native.parse_response(bytes(raw), b'', 0, value)

    def test_R40_R42_old_receipt_and_wire_result_substitutions(self):
        for change in ('source05', 'wire_result'):
            fixture = public_fixture(); self.prepare(fixture)
            if change == 'source05':
                old_receipt = base64.b64decode('ewogICJhcmd2IjogWwogICAgIi91c3IvYmluL3Vuc2hhcmUiLAogICAgIi0tdXNlciIsCiAgICAiLS1tYXAtcm9vdC11c2VyIiwKICAgICItLW1vdW50IiwKICAgICItLXBpZCIsCiAgICAiLS1mb3JrIiwKICAgICItLW1vdW50LXByb2MiLAogICAgIi0tbmV0IiwKICAgICItLXByb3BhZ2F0aW9uIiwKICAgICJwcml2YXRlIiwKICAgICItLWtpbGwtY2hpbGQ9U0lHS0lMTCIsCiAgICAiL3Vzci9iaW4vcHl0aG9uMyIsCiAgICAiLUkiLAogICAgIi1TIiwKICAgICItQiIsCiAgICAiLWMiLAogICAgImltcG9ydCBydW5weSxzeXM7c3lzLnBhdGguaW5zZXJ0KDAsc3lzLmFyZ3ZbMV0pO3N5cy5wYXRoLmluc2VydCgwLHN5cy5hcmd2WzJdKTtydW5weS5ydW5fbW9kdWxlKCdzZW50aW5lbF9idWlsZF9wcm9maWxlJyxydW5fbmFtZT0nX19tYWluX18nKSIsCiAgICAiL2Rldi9zaG0vc2VtYW50aWMtdHJhbnNwb3J0LWxhcmdlLWRvY3VtZW50LTIwMjYxMDMwL3NlbnRpbmVsLTAxL2J1aWxkLWlucHV0LTA0L3Rvb2xzIiwKICAgICIvZGV2L3NobS9zZW1hbnRpYy10cmFuc3BvcnQtbGFyZ2UtZG9jdW1lbnQtMjAyNjEwMzAvc2VudGluZWwtMDEvYnVpbGQtaW5wdXQtMDQvc2VudGluZWxfbmF0aXZlIiwKICAgICIvZGV2L3NobS9zZW1hbnRpYy10cmFuc3BvcnQtbGFyZ2UtZG9jdW1lbnQtMjAyNjEwMzAvc2VudGluZWwtMDEvYnVpbGQtcnVucy9hdHRlbXB0MDQiCiAgXSwKICAiZXh0ZXJuYWxfYnl0ZXMiOiAyNTkwMTU4OCwKICAiZmFpbHVyZSI6IG51bGwsCiAgIm5hbWVzcGFjZV93YWl0ZWQiOiB0cnVlLAogICJyZXR1cm5jb2RlIjogMCwKICAic3RhdHVzIjogIlNFTlRJTkVMX1BPTElDWV9CVUlMRF9URVNUX1BST09GX0NIRUNLRUQiCn0K', validate=True)
                self.assertEqual(digest(old_receipt), '86719321ed4403cb805efecb822f6369b8516f36d90ab383edcb20293e1e0e13')
                put(fixture['registry'], old_receipt)
                fixture['gate']['pure_receipt_pin'] = identity(old_receipt)
            else:
                registry = fixture['registry']; key = fixture['gate']['versioned_manifest_sha256']
                manifest = parse(registry[key]); wanted = manifest['evidence']['wire-result.json']
                raw = json.loads(registry[wanted['sha256']]); raw['worker']['binary']['sha256'] = '0' * 64
                replacement = json.dumps(raw).encode(); put(registry, replacement)
                manifest['evidence']['wire-result.json'] = identity(replacement)
                fixture['gate']['versioned_manifest_sha256'] = put(registry, canonical(manifest))
            with self.subTest(change=change), self.assertRaises(ValueError): self.prepare(fixture)

    def test_R43_R44_exact_evaluator_roster_no_missing_or_unknown_member(self):
        for change in ('missing', 'unknown'):
            fixture = public_fixture(); self.prepare(fixture)
            pin = fixture['gate']['evaluator_manifest_pin']; value = parse(fixture['registry'][pin['sha256']])
            if change == 'missing': value['files'].pop('tools/transport_document_context.py')
            else: value['files']['tools/unknown.py'] = identity(b'unknown')
            raw = canonical(value); put(fixture['registry'], raw)
            fixture['gate']['evaluator_manifest_pin'] = identity(raw)
            with self.subTest(change=change), self.assertRaises(ValueError): self.prepare(fixture)


    def test_R58_R59_R60_parent_rejects_cleanup_writable_or_incomplete(self):
        for change in ('owned_child', 'readonly', 'capture'):
            with tempfile.TemporaryDirectory() as temporary:
                out = Path(temporary)
                record = {'status': native_runtime.SUCCESS, 'readonly_qualified': True,
                    'capture': {'complete': True}, 'failures': [],
                    'cleanup': {'remaining': 0}, 'terminal_cleanup': {'remaining': 0}}
                if change == 'owned_child': record['cleanup']['remaining'] = 1
                elif change == 'readonly': record['readonly_qualified'] = False
                else: record['capture']['complete'] = False
                (out / 'namespace-result.json').write_bytes(canonical(record))
                with patch.object(native_runtime, 'limits'), \
                     patch.object(native_runtime, '_new_output', return_value=out), \
                     patch.object(native_runtime, '_configuration', return_value={}), \
                     patch.object(native_runtime, '_parent', return_value=['MOCK_ONLY']), \
                     patch.object(native_runtime, '_source_identity') as after:
                    with self.subTest(change=change), self.assertRaises(ValueError):
                        native_runtime._run(b'input', Path('/none'), identity(b'binary'), out, {}, 450)
                after.assert_not_called()

    def test_P1_P2_documentary_uncertainty_is_literal_without_truth(self):
        value = projection(); wire = native.encode_projection(value)
        self.assertEqual(wire, WIRE)
        self.assertEqual(value['rounds'][1]['claims'][0]['documentary'], 'NEITHER')
        self.assertEqual(value['rounds'][1]['claims'][1]['documentary'], 'BOTH')
        for answer, expected in zip(value['rounds'][1]['answers'], value['questions']['rows']):
            self.assertEqual(answer['actual'], expected['expected_answer_sha256'])
        result = native.parse_response(OUTPUT, b'', 0, value)
        for key in ('semantic_completeness', 'OCR_accuracy', 'world_truth', 'context_adequacy', 'reference_authentication'):
            self.assertEqual(result[key], 'UNPROVEN')
        self.assertEqual(result['execution_authority'], 'NONE')


    def test_P5_P6_public_prior_blocker_events_retained_with_mask(self):
        for probe, expected in [('Q1', b'\x80'), ('Q2', b'\xc0')]:
            fixture = multi_fixture(); self.prepare(fixture)
            admitted = fixture['gate']['rounds'][0]
            context = parse(fixture['registry'][admitted['context_admission_sha256']])
            context['blockers'][probe] = 'REQUIRED_CONFLICT'
            admitted['context_admission_sha256'] = put(fixture['registry'], canonical(context))
            _wire, prepared = self.prepare(fixture)
            value = prepared['projection']; row = value['rounds'][1]
            self.assertEqual(len(row['prior_events']), 2)
            self.assertEqual(len(row['repair']['prior_blocking_events']), 2)
            self.assertEqual(row['prior_events'], row['repair']['prior_blocking_events'])
            self.assertEqual(native._mask(row['prior_events'], value['probe_ids']), expected + bytes(255))


    def test_R55_parent_memoryerrors_never_leave_spawned_child(self):
        for point in ('buffer', 'pidfd'):
            with tempfile.TemporaryDirectory() as temporary:
                fake = Mock(stdout=io.BytesIO(), stderr=io.BytesIO(), pid=999999, returncode=None)
                target = patch.object(native_runtime, 'bytearray', side_effect=MemoryError, create=True) if point == 'buffer' else patch.object(native_runtime.os, 'pidfd_open', side_effect=MemoryError)
                with patch.object(native_runtime.subprocess, 'Popen', return_value=fake) as spawn, target:
                    with self.assertRaises((MemoryError, ValueError)):
                        native_runtime._parent(Path(temporary), {'source_root': str(ROOT), 'global_deadline': 450})
                if spawn.called:
                    fake.kill.assert_called_once_with()
                    fake.wait.assert_called_once_with(timeout=5)
                else:
                    fake.kill.assert_not_called(); fake.wait.assert_not_called()


if __name__ == '__main__':
    unittest.main()
