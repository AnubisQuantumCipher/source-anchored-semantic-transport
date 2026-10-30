"""Bounded append-only counterexample refinement, with no Python qualification."""
from .common import (NODES, PROBES, ROUNDS, canonical, digest, fields, hash_checked,
                     held_record, integer, label, parse, pin_checked, registry_snapshot, require)
from .bindings import graph_from_registry
from . import challenges

PROFILE = 'sentinel/refinement-history/1'


def affected(graph, changed):
    names = {row['id'] for row in graph['nodes']}
    require(type(changed) is list and len(changed) <= NODES, 'changed node bound')
    active = {label(name) for name in changed}
    require(len(active) == len(changed) and active <= names, 'changed node identity')
    for _ in range(NODES):
        expanded = set(active)
        for edge in graph['edges']:
            if edge['from'] in active or edge['to'] in active:
                expanded.update((edge['from'], edge['to']))
        if expanded == active:
            return sorted(active)
        active = expanded
    raise ValueError('dependency impact bound')


def changed_nodes(previous, current):
    old = {row['id']: row for row in previous['nodes']}
    new = {row['id']: row for row in current['nodes']}
    require(set(old) <= set(new), 'refinement cannot delete original node identities')
    changed = {key for key in old if canonical(old[key]) != canonical(new[key])} | (set(new) - set(old))
    old_edges = {canonical(row) for row in previous['edges']}
    new_edges = {canonical(row) for row in current['edges']}
    for raw in old_edges ^ new_edges:
        row = parse(raw)
        changed.update((row['from'], row['to']))
    return sorted(changed)


def history_checked(previous_raw, held):
    if previous_raw is None:
        require(held is None, 'unexpected previous history identity')
        return None
    value = held_record(previous_raw, held)
    fields(value, ('schema', 'predecessor_sha256', 'test_contract_sha256', 'source_set_sha256',
                   'rounds', 'outcome', 'qualification', 'execution_authority'))
    require(value['schema'] == PROFILE and value['qualification'] == 'NOT_QUALIFIED'
            and value['execution_authority'] == 'NONE', 'history version or authority')
    for key in ('test_contract_sha256', 'source_set_sha256'):
        hash_checked(value[key])
    if value['predecessor_sha256'] is not None:
        hash_checked(value['predecessor_sha256'])
    require(type(value['rounds']) is list and 1 <= len(value['rounds']) <= ROUNDS,
            'history round bound')
    seen, prior_failures = set(), []
    for ordinal, row in enumerate(value['rounds'], 1):
        fields(row, ('ordinal', 'graph_sha256', 'challenge_set_sha256', 'admission_sha256',
            'replay_sha256', 'results', 'changed_nodes', 'invalidated_nodes',
            'repair_parent_sha256s', 'counterexamples'))
        integer(row['ordinal'], ordinal, ordinal)
        for key in ('graph_sha256', 'challenge_set_sha256', 'admission_sha256', 'replay_sha256'):
            hash_checked(row[key])
        require(row['graph_sha256'] not in seen, 'historical refinement cycle')
        seen.add(row['graph_sha256'])
        for key in ('changed_nodes', 'invalidated_nodes'):
            require(type(row[key]) is list and len(row[key]) <= NODES, 'history node list bound')
            require(len({label(name) for name in row[key]}) == len(row[key]), 'duplicate history node')
        require(row['repair_parent_sha256s'] == prior_failures, 'historical failures omitted')
        check_round_results(row)
        prior_failures += [entry['sha256'] for entry in row['counterexamples']]
    clean = all(row['status'] == 'MATCH_REFERENCE' for row in value['rounds'][-1]['results'])
    expected = 'READY_FOR_NATIVE_POLICY_REVIEW' if clean else (
        'EXHAUSTED' if len(value['rounds']) == ROUNDS else 'UNRESOLVED')
    require(value['outcome'] == expected, 'history summary contradicts evidence')
    return value


def check_round_results(row):
    require(type(row['results']) is list and 1 <= len(row['results']) <= PROBES,
            'history result count')
    ids = set()
    for result in row['results']:
        fields(result, ('id', 'claim_id', 'status', 'answer_pin', 'oracle_pin'))
        require(label(result['id']) not in ids, 'duplicate historical result')
        ids.add(result['id']); label(result['claim_id'])
        require(result['status'] in ('UNRUN', 'UNRESOLVED_ORACLE', 'MATCH_REFERENCE',
                                    'MISMATCH_REFERENCE'), 'historical result status')
        for key in ('answer_pin', 'oracle_pin'):
            if result[key] is not None:
                pin_checked(result[key])
    replay = {'schema': 'sentinel/challenge-replay/1', 'challenge_set_sha256': row['challenge_set_sha256'],
        'admission_sha256': row['admission_sha256'], 'results': row['results'],
        'qualification': 'NOT_QUALIFIED', 'execution_authority': 'NONE',
        'semantic_completeness': 'UNPROVEN',
        'scope': 'RECORDED_ANSWER_COMPARISON_TO_HELD_REFERENCE_NOT_MODEL_EXECUTION'}
    require(digest(canonical(replay)) == row['replay_sha256'], 'historical replay edited')
    require(row['counterexamples'] == failures(replay, row['graph_sha256']),
            'historical counterexample removed or changed')


def test_contract(value, admission):
    return digest(canonical({'source_set_sha256': value['source_set_sha256'],
        'probes': value['probes'], 'checker_sha256': admission['checker_sha256'],
        'oracles': admission['oracles']}))


def failures(replay, graph_key):
    result = []
    for row in replay['results']:
        if row['status'] == 'MISMATCH_REFERENCE':
            record = {'schema': 'sentinel/refinement-counterexample/1',
                'candidate_sha256': graph_key, 'replay_sha256': digest(canonical(replay)),
                'probe_id': row['id'], 'claim_id': row['claim_id'],
                'actual_answer_pin': row['answer_pin'], 'oracle_pin': row['oracle_pin'],
                'status': 'CONFIRMED_RELATIVE_TO_HELD_REFERENCE'}
            result.append({'sha256': digest(canonical(record)), 'record': record})
    return result


def recheck_prior(rounds, value, admission_raw, snapshot, registry_held):
    previous_graph = None
    for row in rounds:
        graph = graph_from_registry(row['graph_sha256'], snapshot)
        changed, impacted = [], []
        if previous_graph is not None:
            changed, impacted = impact_details(previous_graph, graph)
        require(row['changed_nodes'] == changed and row['invalidated_nodes'] == impacted,
                'historical dependency impact contradicts retained graphs')
        historical = canonical(dict(value, graph_sha256=row['graph_sha256']))
        admission = canonical(dict(parse(admission_raw), graph_sha256=row['graph_sha256']))
        require(digest(historical) == row['challenge_set_sha256']
                and digest(admission) == row['admission_sha256'], 'historical mandatory tests changed')
        answers = {}
        for result in row['results']:
            if result['answer_pin'] is not None:
                answers[result['id']] = challenges.artifact(result['answer_pin'], snapshot)
        replay = parse(challenges.replay(historical, digest(historical), snapshot, registry_held,
                                         admission, digest(admission), answers))
        require(replay['results'] == row['results'], 'historical result contradicts retained raw answer')
        previous_graph = graph


def impact_details(previous, current):
    changed = changed_nodes(previous, current)
    old_names = {row['id'] for row in previous['nodes']}
    prior = affected(previous, [name for name in changed if name in old_names])
    return changed, sorted(set(prior) | set(affected(current, changed)))


def revision_details(previous, graph, value, contract, allowed, snapshot):
    rounds = previous['rounds']
    require(previous['source_set_sha256'] == value['source_set_sha256'],
            'source revision changed; requires new independently admitted test contract')
    require(previous['test_contract_sha256'] == contract, 'mandatory tests or oracles changed')
    require(value['graph_sha256'] not in {row['graph_sha256'] for row in rounds},
            'refinement cycle or repeated candidate')
    old_graph = graph_from_registry(rounds[-1]['graph_sha256'], snapshot)
    changed, impacted = impact_details(old_graph, graph)
    require(set(changed) == set(allowed), 'unrelated or undeclared interpretation change')
    parents = [entry['sha256'] for row in rounds for entry in row['counterexamples']]
    require(bool(parents), 'refinement needs a retained counterexample')
    return changed, impacted, parents


def advance(previous_raw, previous_held, challenge_raw, challenge_held, registry,
            registry_held, admission_raw, admission_held, answers, allowed_changes):
    answers = challenges.answer_snapshot(answers)
    require(type(allowed_changes) is list and len(allowed_changes) <= NODES, 'allowed change count')
    allowed_changes = parse(canonical(allowed_changes), 32_768)
    previous = history_checked(previous_raw, previous_held)
    require(previous is None or len(previous['rounds']) < ROUNDS, 'refinement budget exhausted')
    snapshot = registry_snapshot(registry, registry_held)
    for raw in answers.values():
        require(snapshot.get(digest(raw)) == raw, 'raw answer not retained in artifact registry')
    value, _snapshot, _oracles = challenges.checked_set(challenge_raw, challenge_held,
        snapshot, registry_held, admission_raw, admission_held)
    graph = graph_from_registry(value['graph_sha256'], snapshot)
    require(type(allowed_changes) is list and len(allowed_changes) <= NODES,
            'allowed change count')
    require(len({label(name) for name in allowed_changes}) == len(allowed_changes),
            'duplicate allowed changes')
    contract = test_contract(value, parse(admission_raw))
    old_rounds = [] if previous is None else previous['rounds']
    changed, impacted, parents = [], [], []
    if previous is not None:
        changed, impacted, parents = revision_details(previous, graph, value, contract,
                                                       allowed_changes, snapshot)
        recheck_prior(old_rounds, value, admission_raw, snapshot, registry_held)
    else:
        require(allowed_changes == [], 'initial candidate has no predecessor changes')
    replay_raw = challenges.replay(challenge_raw, challenge_held, snapshot, registry_held,
                                  admission_raw, admission_held, answers)
    replay = parse(replay_raw)
    row = {'ordinal': len(old_rounds) + 1, 'graph_sha256': value['graph_sha256'],
        'challenge_set_sha256': challenge_held, 'admission_sha256': admission_held,
        'replay_sha256': digest(replay_raw), 'results': replay['results'],
        'changed_nodes': changed, 'invalidated_nodes': impacted,
        'repair_parent_sha256s': parents, 'counterexamples': failures(replay, value['graph_sha256'])}
    clean = all(entry['status'] == 'MATCH_REFERENCE' for entry in replay['results'])
    outcome = 'READY_FOR_NATIVE_POLICY_REVIEW' if clean else (
        'EXHAUSTED' if len(old_rounds) + 1 == ROUNDS else 'UNRESOLVED')
    return canonical({'schema': PROFILE, 'predecessor_sha256': previous_held,
        'test_contract_sha256': contract, 'source_set_sha256': value['source_set_sha256'],
        'rounds': old_rounds + [row], 'outcome': outcome, 'qualification': 'NOT_QUALIFIED',
        'execution_authority': 'NONE'})
