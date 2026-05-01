# SIFT Sentinel Video Demo Script

Target length: 4:30 to 5:00.

## Setup Before Recording

Open these in tabs or terminal panes:

- GitHub repo: `https://github.com/vandit98/sift-sentinel`
- Vercel/project page if public
- Terminal in the repo root
- `cases/demo-case/outputs/demo-run/reports/triage_report.md`
- `cases/demo-case/outputs/demo-run/analysis/execution_log.jsonl`
- `cases/demo-case/outputs/demo-run/analysis/evidence_integrity.json`

Run once before recording so the command history is ready:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## 0:00 - 0:25 Opening

Say:

"Hi, this is SIFT Sentinel, an evidence-safe autonomous DFIR agent for Protocol SIFT and the SANS SIFT Workstation. The goal is to help defenders triage at machine speed without letting the AI mutate evidence or make unsupported claims."

Show:

- Project page or GitHub README.

## 0:25 - 1:10 Architecture

Say:

"The key design decision is that the model does not get arbitrary shell access. SIFT Sentinel exposes typed MCP tools and enforces evidence boundaries in code. Evidence is read-only, generated files go only under the case outputs directory, and every confirmed finding must cite the specific tool call and evidence row behind it."

Show:

- `docs/ARCHITECTURE.md`
- Mention Custom MCP Server, EvidencePolicy, typed forensic tools, logs, and benchmark.

## 1:10 - 2:05 Live Benchmark

Run:

```bash
PYTHONPATH=src python3 -m sift_sentinel benchmark \
  --case cases/demo-case/case.json \
  --run-id video-demo \
  --max-iterations 3
```

Say:

"This runs the autonomous loop against a synthetic, redistributable case with documented ground truth. The benchmark reports precision, recall, false positives, missed truth items, and hallucinated confirmed findings."

Point out:

- Precision `1.0`
- Recall `1.0`
- Hallucination count `0`
- Refuted finding `F-002`

## 2:05 - 2:55 Self-Correction

Run:

```bash
rg "validation_issue|self_correction|agent_iteration" \
  cases/demo-case/outputs/video-demo/analysis/execution_log.jsonl
```

Say:

"The demo includes a deliberate weak lead: `C:\Users\Public\svchost.exe` appears in Prefetch. SIFT Sentinel initially records it as inferred, then asks for Amcache and timeline corroboration. When the evidence does not support it, the agent refutes the lead instead of reporting it as confirmed."

Point out:

- `VAL-002`
- `F-002` changes from inferred to refuted
- Other findings move from inferred to confirmed after corroboration

## 2:55 - 3:40 Evidence Integrity

Run:

```bash
cat cases/demo-case/outputs/video-demo/analysis/evidence_integrity.json
```

Say:

"This is the spoliation proof. SIFT Sentinel hashes the configured evidence before and after the run. The changed, missing, and added lists are empty, so the autonomous run did not modify the evidence."

Then run:

```bash
PYTHONPATH=src python3 -m sift_sentinel spoliation-test \
  --case cases/demo-case/case.json
```

Say:

"The spoliation test tries to write inside evidence paths and confirms those writes are denied by policy."

## 3:40 - 4:25 Report And Audit Trail

Open:

```bash
sed -n '1,180p' cases/demo-case/outputs/video-demo/reports/triage_report.md
```

Say:

"The final report separates confirmed findings from refuted leads. Each confirmed finding includes evidence references, artifact names, row numbers, and tool call IDs. Judges can trace any claim back to the exact tool execution that produced it."

Point out:

- `memory_netstat` row reference
- `memory_malfind` row reference
- `disk_amcache` SHA1 reference
- `registry_run_keys` reference

## 4:25 - 4:55 Closing

Say:

"SIFT Sentinel is built around a simple rule: autonomy is useful only when it remains auditable. This project combines a custom MCP server, typed forensic tools, evidence integrity checks, self-correction, and benchmark scoring so defenders can move quickly without sacrificing trust."

Show:

- GitHub repo URL
- Try-it-out instructions

## Devpost Video Upload

Upload the recording as unlisted to YouTube or Vimeo, then paste that URL into Devpost's "Video demo link" field.

