# Cyber Gym (minimal)

A small, **safe** starting point for creating labeled, cyber-style telemetry
without using production security data. It makes deterministic, simulated event
sequences from scenario manifests, validates their schema and causal order, and
can optionally ask a NVIDIA-hosted model to author a detection *description*.

It deliberately does not execute attacks, scan systems, or connect to any
environment other than the optional NVIDIA inference endpoint.

## Quick start

```powershell
cd C:\Users\zcharpy\Documents\cyber-gym
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

python cyber_gym.py generate --runs 10
python cyber_gym.py validate
```

The generated, clearly labeled simulation is written to
`data/generated/telemetry.jsonl`. The command prints its ground-truth labels.

Three scenario templates ship with the example: unusual process ancestry,
authentication burst, and cloud permission change. Each run varies the demo
host/user and includes a small benign baseline. Generate one scenario with:

```powershell
python cyber_gym.py generate --scenario authentication-burst-001 --runs 25
```

Use `--no-benign` when you only want the labeled scenario events.

## Generate richer examples

The generator now supports three safe, clearly labeled scenario templates:

- unusual process ancestry;
- authentication burst followed by access; and
- cloud permission change followed by service-identity use.

Each `--runs` iteration produces a deterministic variation with a different
demo host/user and, by default, three benign background events. The output
retains `run_id`, `scenario_id`, `technique`, `ground_truth`, and
`event_index`, so it can be replayed and validated as a coherent sequence.

```powershell
# All scenarios, 10 variations of each
python cyber_gym.py generate --runs 10
python cyber_gym.py validate

# One scenario with 25 variations
python cyber_gym.py generate --scenario authentication-burst-001 --runs 25

# Labeled events only; omit the benign baseline
python cyber_gym.py generate --scenario cloud-permission-change-001 --runs 10 --no-benign
```

For example, `python cyber_gym.py generate --runs 4` produces 12 labeled runs
and 80 events; `python cyber_gym.py validate` verifies event indexes and the
expected causal order of every labeled sequence. To add a new scenario, copy a
file in `scenarios/`, give it a unique `scenario_id`, define its `events` and
`expected_event_kinds`, then rerun generation and validation.

## Detect anomalies and evaluate coverage

`validate` is intentionally an integrity check: it confirms the generator
wrote coherent events. It is not an anomaly detector, so a correctly generated
dataset should pass validation.

Use `detect` to apply the included transparent detection rules and print each
finding. Use `evaluate` to compare detected runs with the synthetic
ground-truth labels.

```powershell
python cyber_gym.py generate --runs 10
python cyber_gym.py validate
python cyber_gym.py detect
python cyber_gym.py evaluate
```

The initial rules flag: unusual office-process ancestry plus network activity,
three failed authentications followed by success and protected-service access,
and a cloud permission change followed by protected API use.

## Add organization golden seeds

You can import approved, sanitized organization data as **golden seeds**. This
is local-only: the importer never makes a network call. Imported seeds are kept
under `data/seeds/`, which is excluded by `.gitignore`. Do not commit real
telemetry, secrets, credentials, personal data, internal hostnames, or customer
identifiers. Follow your organization's data-access and security-review process
before importing anything.

There are two seed statuses:

- `labeled`: records have an analyst/reviewer label and can be used as trusted
  evaluation material;
- `unlabeled`: records have no such claim and should be reviewed or labeled
  before using them for evaluation.

Accepted input formats are JSONL (one object per line), a JSON array (or an
object containing `records`), and CSV. Every record must include `timestamp`
and `event`; `event` is a JSON object, or a JSON-encoded string in a CSV cell.
Labeled records must also include a `label` object (or a JSON-encoded `label`
CSV cell). Recommended label fields are `anomalous` (boolean), `technique`, and
`expected_detection`.

Labeled JSONL example:

```json
{"timestamp":"2026-02-01T10:12:00Z","source":"approved-sanitized-export","event":{"kind":"authentication","outcome":"failure","method":"interactive","source_category":"organization-managed-endpoint","user":"redacted-user"},"label":{"anomalous":true,"technique":"T1110","expected_detection":"Repeated authentication failures require review."}}
```

An unlabeled record has the same `timestamp`, optional `source`, and `event`,
but no `label`. Ready-to-copy samples are in
[`samples/`](samples/).

```powershell
# Import a reviewed labeled seed set
python cyber_gym.py import-seeds --input C:\approved\sanitized_labeled.jsonl --seed-status labeled

# Import an unlabeled seed set
python cyber_gym.py import-seeds --input C:\approved\sanitized_unlabeled.csv --seed-status unlabeled

# Append imported seeds to a generated local output file
python cyber_gym.py generate --runs 10 --include-seeds
```

Imported records retain `dataset_type: golden_seed`, `provenance`, and
`seed_status`, so they remain distinguishable from simulated data. Integrity
validation skips golden seeds because they are not required to match this
project's three toy scenario schemas. The model-assisted `author-rule` command
also excludes golden seeds deliberately, preventing accidental transmission of
organization data to the inference endpoint.

## Optional model-assisted detection authoring

Set the key only in your shell; never put it in source files:

```powershell
$env:NVIDIA_API_KEY = "..."
python cyber_gym.py author-rule
```

The default model is `nvidia/moonshotai/kimi-k3`; change it with
`--model <model-id>`. The request uses `requests` against NVIDIA's inference
endpoint.

## Turning this into real telemetry

Keep this project as the dataset contract and validation layer. Replace
`build_events` with an approved lab collector that imports events from a
disposable, instrumented cyber range. Preserve the `scenario_id`,
`event_index`, `technique`, and `expected_detection` fields so every run retains
ground truth and can be replayed through detection rules.
