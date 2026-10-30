# Russia–Ukraine Hacktivism dashboard

## *The dashboard was entirely generated using AI*

An interactive view over the DDoS attack graph built in `../analysis.ipynb`, focused on
hacktivist activity in the Russia–Ukraine war.

## Files

| File | What it is |
|---|---|
| `index.html` | The dashboard. Self-contained apart from the two JSON files beside it. |
| `dashboard.json` | The exported graph (3.4 MB). Rebuild it with `build_dashboard.py`. |
| `countries-110m.json` | Natural Earth country shapes at 1:110m, from [world-atlas](https://github.com/topojson/world-atlas). |
| `build_dashboard.py` | Runs the notebook pipeline and writes `dashboard.json`. |
| `actors.py` | The actor taxonomy: what is not an actor, which names are the same actor, and which side each actor is on. |

## Rebuilding the data

```bash
python dashboard/build_dashboard.py
```

It executes the code cells of `analysis.ipynb` (skipping the `%pip` and Neo4j cells), so the
notebook stays the single source of truth for parsing, event clustering and the Wikidata
sector lookup. With `wikidata_cache.json` present the run is offline and takes about a
minute; without it the notebook will call the Wikidata API for every victim.

## Viewing it

The page fetches its JSON, so `file://` will not work — serve the folder:

```bash
python -m http.server 8000 --directory dashboard
```

then open <http://127.0.0.1:8000/>. Any static host works for publishing (GitHub Pages,
Netlify, a university web space): upload the four files in this folder as they are.

## What the dashboard shows

- **Map** — victims, attackers, or cross-border flows. The choropleth runs light to dark
  with rising attack counts in both light and dark themes.
- **Russia and Ukraine, sector by sector** — the two countries' victims side by side, as
  counts or as each country's own share, with a skew column showing which sectors are
  disproportionately hit on each side.
- **Attacks per month, by side** — Russia-aligned, Ukraine-aligned and unattributed series
  against the 24 February 2022 line.
- **Who is attacking** — actor ranking with a profile card: side, coding reason, active
  period, top victim sectors and countries.
- **Attack events** — sortable, paginated browser over every event in the current filter,
  with a per-event record and a link to the original report, plus the actor–target graph.

## Caveats to carry into the writing

1. **Side is hand-coded.** `actors.py` codes each collective from public reporting; the
   reason sits next to each entry. It is a coding sheet to argue with, not ground truth.
2. **Bare allegiance phrases are dropped.** `pro-Russian hackers` names a side but no actor,
   so it is dropped rather than counted, which makes the Russia-aligned totals conservative.
3. **Country attribution is weak.** The extraction gives locations per story, not per entity,
   so a victim's country is the one it co-occurs with most across its coverage. Countries
   from Wikidata `P17` are badged and the toggle restricts the whole dashboard to them —
   use that for anything you intend to publish. Attacker countries have no such source.
4. **Coverage is not incidence.** Everything here counts what the press reported, so
   reporting bias (Western outlets, English-language sources, newsworthy victims) is baked
   into every figure. The pro-Russian to pro-Ukrainian ratio in particular reflects which
   collectives court publicity as much as who is more active.
