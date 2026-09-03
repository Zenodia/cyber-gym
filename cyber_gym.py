"""Create labeled, simulated cyber telemetry from safe scenario manifests."""
from __future__ import annotations

import argparse
import csv
import json
import os
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parent
SCENARIOS_DIR = ROOT / "scenarios"
OUTPUT_PATH = ROOT / "data" / "generated" / "telemetry.jsonl"
SEEDS_DIR = ROOT / "data" / "seeds"


def load_scenarios(name: str) -> list[dict[str, Any]]:
    scenarios = [json.loads(path.read_text(encoding="utf-8")) for path in sorted(SCENARIOS_DIR.glob("*.json"))]
    if name == "all":
        return scenarios
    selected = [scenario for scenario in scenarios if scenario["scenario_id"] == name]
    if not selected:
        raise ValueError("Unknown scenario. Use --scenario all or one of: " + ", ".join(s["scenario_id"] for s in scenarios))
    return selected


def benign_events(run_id: str, started: datetime) -> list[dict[str, Any]]:
    baseline = [
        {"kind": "process", "image": "browser.exe", "parent_image": "explorer.exe", "user": "demo_user"},
        {"kind": "network", "image": "browser.exe", "destination_category": "software-update", "user": "demo_user"},
        {"kind": "authentication", "outcome": "success", "method": "interactive", "source_category": "test-client", "user": "demo_user"},
    ]
    return [{"timestamp": (started + timedelta(seconds=index * 11)).isoformat(), "dataset_type": "simulated_cyber_telemetry", "run_id": run_id, "event_index": index, "ground_truth": False, "event": event} for index, event in enumerate(baseline)]


def build_events(scenario: dict[str, Any], run_number: int, include_benign: bool) -> list[dict[str, Any]]:
    """Deterministic variations; replace this function with approved lab collection later."""
    run_id = f"{scenario['scenario_id']}-run-{run_number:03d}"
    started = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc) + timedelta(minutes=run_number * 7)
    events = benign_events(run_id, started) if include_benign else []
    hosts, users = ["lab-ws-01", "lab-ws-02", "lab-ws-03"], ["demo_user", "demo_analyst", "demo_operator"]
    for index, source in enumerate(scenario["events"]):
        event = deepcopy(source)
        if "user" in event:
            event["user"] = users[run_number % len(users)]
        event["host"] = hosts[run_number % len(hosts)]
        events.append({"timestamp": (started + timedelta(seconds=(len(events)) * 17)).isoformat(), "dataset_type": "simulated_cyber_telemetry", "run_id": run_id, "scenario_id": scenario["scenario_id"], "event_index": len(events), "technique": scenario["technique"], "ground_truth": True, "event": event})
    return events


def write_jsonl(events: list[dict[str, Any]]) -> None:
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")


def read_seed_input(path: Path) -> list[dict[str, Any]]:
    """Read JSONL, JSON-array, or CSV seed records without sending them anywhere."""
    if path.suffix.lower() == ".jsonl":
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if path.suffix.lower() == ".json":
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, list) else value["records"]
    if path.suffix.lower() == ".csv":
        with path.open(encoding="utf-8", newline="") as handle:
            return list(csv.DictReader(handle))
    raise ValueError("Seed input must be .jsonl, .json, or .csv")


def import_seeds(path: Path, status: str) -> Path:
    records = read_seed_input(path)
    canonical = []
    for index, record in enumerate(records):
        if "timestamp" not in record or "event" not in record:
            raise ValueError(f"Seed record {index} must contain timestamp and event")
        event = record["event"]
        if isinstance(event, str):
            event = json.loads(event)
        if not isinstance(event, dict):
            raise ValueError(f"Seed record {index}: event must be an object or JSON object string")
        label = record.get("label")
        if isinstance(label, str) and label:
            label = json.loads(label)
        if status == "labeled" and not isinstance(label, dict):
            raise ValueError(f"Labeled seed record {index} must contain a label object")
        canonical.append({"timestamp": record["timestamp"], "source": record.get("source", "organization-golden-seed"), "event": event, "label": label})
    destination = SEEDS_DIR / status / f"{path.stem}.jsonl"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("".join(json.dumps(record) + "\n" for record in canonical), encoding="utf-8")
    return destination


def load_imported_seeds() -> list[dict[str, Any]]:
    events = []
    for status in ("labeled", "unlabeled"):
        for path in sorted((SEEDS_DIR / status).glob("*.jsonl")):
            for index, record in enumerate(read_seed_input(path)):
                label = record.get("label") if status == "labeled" else None
                events.append({"timestamp": record["timestamp"], "dataset_type": "golden_seed", "provenance": "organization-golden-seed", "seed_status": status, "run_id": f"golden-seed-{path.stem}", "event_index": index, "ground_truth": bool(label and label.get("anomalous", False)), "event": record["event"], "label": label})
    return events


def read_jsonl() -> list[dict[str, Any]]:
    if not OUTPUT_PATH.exists():
        raise FileNotFoundError("Run `python cyber_gym.py generate` first.")
    return [json.loads(line) for line in OUTPUT_PATH.read_text(encoding="utf-8").splitlines() if line]


def validate(events: list[dict[str, Any]], scenarios: list[dict[str, Any]]) -> list[str]:
    errors, by_id, runs = [], {s["scenario_id"]: s for s in scenarios}, {}
    required = {"timestamp", "dataset_type", "run_id", "event_index", "ground_truth", "event"}
    for event in events:
        if event.get("dataset_type") == "golden_seed":
            continue
        if missing := required - event.keys():
            errors.append(f"missing {sorted(missing)}")
        runs.setdefault(event.get("run_id", "missing"), []).append(event)
    for run_id, run_events in runs.items():
        if [event["event_index"] for event in run_events] != list(range(len(run_events))):
            errors.append(f"{run_id}: event indexes are not sequential")
        labeled = [event for event in run_events if event["ground_truth"]]
        if labeled:
            scenario = by_id.get(labeled[0].get("scenario_id"))
            kinds = [event["event"]["kind"] for event in labeled]
            if not scenario or kinds != scenario["expected_event_kinds"]:
                errors.append(f"{run_id}: unexpected labeled event order")
    return errors


def detect(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Run small transparent detection rules against every simulated run."""
    runs: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        runs.setdefault(event["run_id"], []).append(event)

    findings = []
    for run_id, run_events in runs.items():
        records = [event["event"] for event in run_events]
        kinds = [record["kind"] for record in records]
        if (
            "process" in kinds
            and any(record.get("image") == "script_interpreter.exe" and record.get("parent_image") == "office_app.exe" for record in records)
            and any(record.get("kind") == "network" and record.get("image") == "script_interpreter.exe" for record in records)
        ):
            findings.append({"run_id": run_id, "rule_id": "unusual-process-ancestry", "severity": "medium", "reason": "Office-process parent launched a script interpreter that made a network connection."})

        failed_auth = sum(record.get("kind") == "authentication" and record.get("outcome") == "failure" for record in records)
        successful_auth = any(record.get("kind") == "authentication" and record.get("outcome") == "success" for record in records)
        protected_access = any(record.get("kind") == "service_access" and record.get("outcome") == "success" for record in records)
        if failed_auth >= 3 and successful_auth and protected_access:
            findings.append({"run_id": run_id, "rule_id": "authentication-burst-followed-by-access", "severity": "high", "reason": "Three or more failed authentications were followed by success and protected-service access."})

        role_change = any(record.get("kind") == "identity_change" and record.get("action") == "role-assignment-applied" for record in records)
        protected_read = any(record.get("kind") == "cloud_api" and record.get("action") == "protected-read" and record.get("outcome") == "success" for record in records)
        if role_change and protected_read:
            findings.append({"run_id": run_id, "rule_id": "permission-change-followed-by-use", "severity": "high", "reason": "A simulated permission change was followed by successful protected API use."})
    return findings


def evaluate(events: list[dict[str, Any]], findings: list[dict[str, Any]]) -> dict[str, Any]:
    expected = {event["run_id"] for event in events if event["dataset_type"] == "simulated_cyber_telemetry" and event["ground_truth"]}
    detected = {finding["run_id"] for finding in findings}
    return {
        "expected_anomalous_runs": len(expected),
        "detected_anomalous_runs": len(detected),
        "false_negatives": sorted(expected - detected),
        "false_positives": sorted(detected - expected),
    }


def author_rule(events: list[dict[str, Any]], model: str) -> str:
    import requests
    api_key = os.environ.get("NVIDIA_API_KEY")
    if not api_key:
        raise RuntimeError("Set NVIDIA_API_KEY before using author-rule.")
    prompt = {"task": "Write one vendor-neutral detection specification for the labeled simulated events.", "constraints": ["Use only visible fields.", "No real hosts, users, IPs, or payloads.", "Return JSON."], "events": [event for event in events if event["dataset_type"] == "simulated_cyber_telemetry" and event["ground_truth"]]}
    response = requests.post("https://inference-api.nvidia.com/v1/chat/completions", headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}, json={"model": model, "messages": [{"role": "system", "content": "You are a careful defensive detection engineer."}, {"role": "user", "content": json.dumps(prompt)}], "temperature": 0.2, "max_tokens": 800}, timeout=60)
    response.raise_for_status()
    return response.json()["choices"][0]["message"]["content"]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["generate", "import-seeds", "validate", "detect", "evaluate", "author-rule"])
    parser.add_argument("--scenario", default="all", help="Scenario ID or 'all'.")
    parser.add_argument("--runs", type=int, default=3, help="Variations per scenario.")
    parser.add_argument("--no-benign", action="store_true", help="Omit benign baseline events.")
    parser.add_argument("--include-seeds", action="store_true", help="Append locally imported golden seeds to generated output.")
    parser.add_argument("--input", type=Path, help="Seed file to import (.jsonl, .json, or .csv).")
    parser.add_argument("--seed-status", choices=["labeled", "unlabeled"], help="Whether imported records contain label objects.")
    parser.add_argument("--model", default="nvidia/moonshotai/kimi-k3")
    args = parser.parse_args()
    if args.command == "import-seeds":
        if not args.input or not args.seed_status:
            raise SystemExit("import-seeds requires --input <file> and --seed-status labeled|unlabeled")
        print(f"Imported seeds to {import_seeds(args.input, args.seed_status)}")
    elif args.command == "generate":
        if args.runs < 1:
            raise SystemExit("--runs must be at least 1")
        events = [event for scenario in load_scenarios(args.scenario) for run in range(args.runs) for event in build_events(scenario, run, not args.no_benign)]
        if args.include_seeds:
            events.extend(load_imported_seeds())
        write_jsonl(events)
        print(f"Wrote {len(events)} events to {OUTPUT_PATH}")
    else:
        events = read_jsonl()
        if args.command == "validate":
            if errors := validate(events, load_scenarios("all")):
                raise SystemExit("Validation failed:\n- " + "\n- ".join(errors))
            print(f"Validation passed for {len(events)} events.")
        elif args.command == "detect":
            findings = detect(events)
            print(json.dumps(findings, indent=2))
            print(f"Detected {len(findings)} anomaly findings.")
        elif args.command == "evaluate":
            print(json.dumps(evaluate(events, detect(events)), indent=2))
        else:
            print(author_rule(events, args.model))


if __name__ == "__main__":
    main()
