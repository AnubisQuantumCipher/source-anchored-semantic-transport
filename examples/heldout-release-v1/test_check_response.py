"""Deterministic rejection controls for the held-out response checker."""
import json
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).absolute().parent))
import check_response as checker

HERE = Path(__file__).absolute().parent
FIXTURE_RAW = (HERE / 'fixture.json').read_bytes()
CRITERIA_RAW = (HERE / 'criteria.json').read_bytes()
FIXTURE = json.loads(FIXTURE_RAW)
SOURCES = {item['id']: item['text'] for item in FIXTURE['sources']}
GOOD = ('rights_review_complete and curatorial_review_complete and '
        '0 <= age_days <= 2 and (not publication_hold or maintenance_replacement)')


def encoded(value):
    return json.dumps(value, ensure_ascii=False).encode('utf-8')


def response():
    before = SOURCES['CODE'].splitlines()[1].strip()[len('return '):]
    return dict(schema='transport/heldout-release-response/1',
                replacement=dict(schema='transport/function-replacement/1', source_id='CODE',
                                 base_sha256=checker.sha(SOURCES['CODE'].encode()),
                                 before=before, after=GOOD),
                current_rule='Both reviews and inclusive ages; narrow hold exception.',
                historical_authority='COR-02 superseded; HAPP-M1 withdrawn; draft only.',
                historical_verification='North and South conflict; provenance unresolved; UNKNOWN.',
                actions=[dict(id=identifier, state=state)
                         for identifier, state in checker.LEDGER.items()],
                unresolved=['Historical report provenance remains unresolved.'],
                source_citations=[dict(source=name, quote=SOURCES[name].splitlines()[0])
                                  for name in ('RULE', 'HISTORY', 'REPORTS', 'ACTIONS')])


def assess(value):
    return checker.assess(FIXTURE_RAW, CRITERIA_RAW, encoded(value))


class ResponseTests(unittest.TestCase):
    def test_fixture_derived_valid_response(self):
        result = assess(response())
        self.assertEqual(result['status'], 'DETERMINISTIC_CHECKS_PASSED')
        self.assertEqual(result['behavior']['state_count'], 80)
        self.assertEqual(result['behavior']['failures'], 0)
        self.assertEqual(result['behavior']['actual_bits'], checker.BITS)
        self.assertEqual(result['execution_authority'], 'NONE')
        self.assertEqual(result['narrative_fidelity'], 'NOT_ASSESSED')

    def test_wrong_full_before_and_base_are_refused(self):
        mutations = [('before', ' or '), ('before', 'return ' + response()['replacement']['before']),
                     ('base_sha256', '0' * 64), ('base_sha256', checker.CODE_SHA256.upper()),
                     ('source_id', 'RULE'), ('schema', 'wrong')]
        for key, value in mutations:
            with self.subTest(key=key, value=value):
                item = response()
                item['replacement'][key] = value
                self.assertEqual(assess(item)['status'], 'REFUSED')

    def test_signature_and_unsupported_expressions_are_refused(self):
        expressions = ['True\ndef other():\n    return True',
                       'True\n    pass', 'True; pass', 'True;', 'True # comment',
                       'bool(rights_review_complete)', '__import__("os")',
                       'age_days + 1 == 2', 'rights_review_complete == 1', 'age_days',
                       'all(x for x in (True,))', 'True if rights_review_complete else False',
                       'rights_review_complete.real', '[True][0]', '(x := True)', '']
        for expression in expressions:
            with self.subTest(expression=expression):
                item = response()
                item['replacement']['after'] = expression
                self.assertEqual(assess(item)['status'], 'REFUSED')

    def test_all_original_predicate_negative_controls_fail(self):
        criteria = json.loads(CRITERIA_RAW)
        self.assertLessEqual(len(criteria['required_negative_controls']), 16)
        for control in criteria['required_negative_controls']:
            with self.subTest(control=control['id']):
                item = response()
                item['replacement']['after'] = control['expression']
                result = assess(item)
                self.assertEqual(result['status'], 'FINITE_TABLE_FAILED')
                self.assertGreater(result['behavior']['failures'], 0)
                self.assertTrue(result['behavior']['first_mismatches'])

    def test_lower_endpoint_exclusive_mutant_fails(self):
        item = response()
        item['replacement']['after'] = GOOD.replace('0 <=', '0 <')
        result = assess(item)
        self.assertEqual(result['status'], 'FINITE_TABLE_FAILED')
        self.assertEqual(result['behavior']['first_mismatches'][0]['state']['age_days'], 0)

    def test_closed_objects_and_required_field_types(self):
        for location in ('top', 'replacement', 'action', 'citation'):
            with self.subTest(location=location):
                item = response()
                target = {'top': item, 'replacement': item['replacement'],
                          'action': item['actions'][0], 'citation': item['source_citations'][0]}
                target[location]['extra'] = True
                self.assertEqual(assess(item)['status'], 'REFUSED')
        for name, bad in (('schema', 'wrong'), ('actions', {}), ('unresolved', [False]),
                          ('current_rule', True), ('historical_authority', None),
                          ('historical_verification', []), ('source_citations', 'RULE')):
            with self.subTest(name=name):
                item = response()
                item[name] = bad
                self.assertEqual(assess(item)['status'], 'REFUSED')
        item = response()
        del item['current_rule']
        self.assertEqual(assess(item)['status'], 'REFUSED')

    def test_complete_ledger_states_and_unique_identifiers(self):
        for mutation in ('missing', 'duplicate', 'wrong_state', 'wrong_id', 'wrong_type'):
            with self.subTest(mutation=mutation):
                item = response()
                if mutation == 'missing':
                    item['actions'].pop()
                elif mutation == 'duplicate':
                    item['actions'][1] = item['actions'][0]
                elif mutation == 'wrong_state':
                    item['actions'][2]['state'] = 'COMPLETED'
                elif mutation == 'wrong_id':
                    item['actions'][2]['id'] = 'M-ACT-99'
                else:
                    item['actions'][2]['state'] = False
                self.assertEqual(assess(item)['status'], 'REFUSED')

    def test_ledger_order_is_unspecified_and_reordering_passes(self):
        item = response()
        item['actions'].reverse()
        self.assertEqual(assess(item)['status'], 'DETERMINISTIC_CHECKS_PASSED')

    def test_citation_coverage_and_exact_contiguous_quotes(self):
        for index in range(4):
            item = response()
            del item['source_citations'][index]
            self.assertEqual(assess(item)['status'], 'REFUSED')
        for source, quote in (('NO-SOURCE', 'text'), ('RULE', ''), ('RULE', 'not in source'),
                              ('RULE', 'Return True ... replacement is True.')):
            with self.subTest(source=source, quote=quote):
                item = response()
                item['source_citations'][0] = dict(source=source, quote=quote)
                self.assertEqual(assess(item)['status'], 'REFUSED')

    def test_json_rejections_and_byte_bounds(self):
        malformed = [b'{}{}', b'{"schema":1,"schema":2}', b'\xef\xbb\xbf{}', b'\xff',
                     b'[]', b'null', b'{"x":NaN}', b' ' * (checker.CAP + 1)]
        for raw in malformed:
            with self.subTest(raw=raw[:40]):
                result = checker.assess(FIXTURE_RAW, CRITERIA_RAW, raw)
                self.assertEqual(result['status'], 'REFUSED')

    def test_frozen_oracle_code_and_signature_changes_refuse(self):
        criteria = json.loads(CRITERIA_RAW)
        criteria['oracle']['expected_bits'] = '1' * 80
        self.assertEqual(checker.assess(FIXTURE_RAW, encoded(criteria), encoded(response()))
                         ['status'], 'REFUSED')
        for mutation in ('source', 'signature', 'domain'):
            fixture = json.loads(FIXTURE_RAW)
            if mutation == 'source':
                fixture['sources'][0]['text'] += '\n'
            elif mutation == 'signature':
                fixture['parameters'].reverse()
            else:
                fixture['domains']['age_days']['min'] = False
            self.assertEqual(checker.assess(encoded(fixture), CRITERIA_RAW, encoded(response()))
                             ['status'], 'REFUSED')

    def test_runtime_exact_types_are_not_python_truthiness(self):
        program = checker.parse_function((SOURCES['CODE'].splitlines()[0] +
                                          '\n    return ' + GOOD + '\n').encode(),
                                         checker.FUNCTION, checker.PARAMETERS, checker.DOMAINS)
        from transport_fixture_expression import evaluate
        valid = dict(zip(checker.PARAMETERS, (True, True, False, False, 1), strict=True))
        for name, value in (('age_days', True), ('rights_review_complete', 1),
                            ('curatorial_review_complete', 0), ('publication_hold', 0),
                            ('maintenance_replacement', 1)):
            state = dict(valid)
            state[name] = value
            with self.subTest(name=name), self.assertRaises(ValueError):
                evaluate(program, state)

    def test_narrative_semantics_are_explicitly_unassessed(self):
        item = response()
        item['historical_authority'] = 'This deliberately unsupported narrative is not scored here.'
        item['historical_verification'] = 'Not a claim checked by this deterministic adapter.'
        result = assess(item)
        self.assertEqual(result['status'], 'DETERMINISTIC_CHECKS_PASSED')
        for name in ('narrative_fidelity', 'historical_authentication', 'authority_meaning',
                     'uncertainty_meaning', 'task_only_access'):
            self.assertEqual(result[name], 'NOT_ASSESSED')


if __name__ == '__main__':
    unittest.main()
