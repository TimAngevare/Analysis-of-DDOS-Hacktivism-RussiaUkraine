"""Build `dashboard.json` from the pipeline in `analysis.ipynb`.

The notebook stays the single source of truth for parsing, event clustering and the
Wikidata sector lookup. This script executes its code cells (skipping the `%pip` and
Neo4j ones, which need a running database), then applies the dashboard's own layer:
the actor taxonomy in `actors.py`, the war-phase split, and a slimmed JSON payload.

    python dashboard/build_dashboard.py

Needs `wikidata_cache.json` beside the notebook - with it the build is offline and
takes about a minute. Without it the notebook cells will call the Wikidata API for
every victim, which takes hours.
"""

import json
import os
import re
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
NOTEBOOK = os.path.join(ROOT, 'analysis.ipynb')

sys.path.insert(0, HERE)
import actors  # noqa: E402

# Cells that talk to Neo4j or install packages; everything else is pipeline.
SKIP = re.compile(r'%pip|neo4j|GraphDatabase|driver\.|NEO4J_')


def run_notebook():
    """Execute the notebook's pipeline cells and return their shared namespace."""
    nb = json.load(open(NOTEBOOK, encoding='utf-8'))
    code = [''.join(c['source']) for c in nb['cells'] if c['cell_type'] == 'code']
    pipeline = [src for src in code if src.strip() and not SKIP.search(src)]

    cwd = os.getcwd()
    os.chdir(ROOT)  # the notebook reads './parsed-ext-filtered.csv'
    namespace = {'__name__': '__notebook__'}
    try:
        for i, src in enumerate(pipeline):
            try:
                exec(compile(src, f'<notebook cell {i}>', 'exec'), namespace)
            except Exception as exc:
                raise RuntimeError(f'notebook cell {i} failed: {exc}\n\n{src[:400]}') from exc
    finally:
        os.chdir(cwd)
    return namespace


def canonical_groups(events_groups):
    """Resolve raw group strings to canonical actor names.

    `actors.ALIASES` covers the actors worth naming. Anything else that survives the
    drop lists keeps its own spelling, with case and punctuation variants folded onto
    the most frequent spelling in the data.
    """
    spellings = defaultdict(Counter)
    for names in events_groups:
        for raw in names:
            if actors.is_dropped(raw) or actors.alias(raw):
                continue
            spellings[actors.key(raw)][raw] += 1
    fallback = {k: c.most_common(1)[0][0] for k, c in spellings.items()}

    def resolve(raw):
        if actors.is_dropped(raw):
            return None
        return actors.alias(raw) or fallback.get(actors.key(raw))

    return resolve


def main():
    print('running the notebook pipeline...')
    ns = run_notebook()
    attack_events = ns['attack_events']
    victim_sectors = ns['victim_sectors']
    nodes = ns['nodes']
    pd = ns['pd']

    events_raw = attack_events.to_dict('records')
    resolve = canonical_groups(e['groups'] for e in events_raw)

    wd_country = victim_sectors['wikidata_country'].dropna().to_dict()
    node_by = {(n['label'], n['name']): n for n in nodes}

    # A group's country is only ever story co-occurrence, so it is kept as context on
    # the actor record rather than used to place attacks on the map.
    group_votes = defaultdict(Counter)
    for (label, name), n in node_by.items():
        if label != 'Group':
            continue
        canonical = resolve(name)
        if canonical:
            for rank, country in enumerate(n['countries']):
                group_votes[canonical][country] += len(n['countries']) - rank

    events, dropped = [], 0
    for e in events_raw:
        groups = []
        for raw in e['groups']:
            c = resolve(raw)
            if c and c not in groups:
                groups.append(c)
        dropped += len(e['groups']) - len(groups)

        target = node_by.get((e['target_label'], e['target_name']), {})
        wd = wd_country.get(e['target_name'])
        first = e['first_seen'].date().isoformat()
        aligns = sorted({actors.alignment_of(g) for g in groups})

        events.append({
            'id': e['event_id'],
            'tl': e['target_label'],
            'tn': e['target_name'],
            'f': first,
            'l': e['last_seen'].date().isoformat(),
            'n': int(e['n_stories']),
            'g': groups,
            'al': aligns,
            'm': e['motives'][:4],
            'c': e['costs'][:3],
            'co': e['countries'][:6],
            't': (e['titles'][0] or '')[:170] if e['titles'] else None,
            'u': e['links'][0] if e['links'] else None,
            'sec': target.get('sector'),
            'ss': target.get('sector_source'),
            'vc': wd or target.get('country'),          # victim country, best available
            'vcs': 'wikidata' if wd else ('stories' if target.get('country') else None),
            'war': first >= actors.INVASION,
        })

    out_actors = []
    for name in sorted({g for e in events for g in e['g']}):
        votes = group_votes.get(name, Counter())
        out_actors.append({
            'n': name,
            'al': actors.alignment_of(name),
            'note': actors.note_of(name),
            'c': votes.most_common(1)[0][0] if votes else None,
        })

    out_targets = []
    for (label, name), n in node_by.items():
        if label == 'Group':
            continue
        out_targets.append({
            'l': label, 'n': name,
            'vc': n.get('wikidata_country') or n['country'],
            'vcs': 'wikidata' if n.get('wikidata_country') else (
                'stories' if n['country'] else None),
            'sec': n['sector'], 'ss': n['sector_source'], 'd': n['wikidata_description'],
        })

    payload = {
        'generated': pd.Timestamp.utcnow().strftime('%Y-%m-%d'),
        'n_stories': int(len(ns['stories'])),
        'invasion': actors.INVASION,
        'alignments': [actors.PRO_RU, actors.PRO_UA, actors.RU_STATE, actors.UA_STATE,
                       actors.CRIMINAL, actors.OTHER],
        'hacktivist': sorted(actors.HACKTIVIST),
        'dropped_mentions': dropped,
        'actors': out_actors,
        'targets': out_targets,
        'events': events,
    }

    path = os.path.join(HERE, 'dashboard.json')
    json.dump(payload, open(path, 'w', encoding='utf-8'),
              ensure_ascii=False, separators=(',', ':'))

    named = [e for e in events if e['g']]
    war = [e for e in events if e['war']]
    print(f"\n{len(events)} attack events, {len(named)} with a named actor, "
          f"{len(war)} on or after the invasion")
    print(f"{dropped} group mentions dropped as techniques / adjectives / outlets")
    print('events by alignment:')
    for a, n in Counter(a for e in events for a in e['al']).most_common():
        print(f"  {n:6d}  {a}")
    print(f"\nwrote {path}  {os.path.getsize(path) / 1e6:.2f} MB")


if __name__ == '__main__':
    main()
