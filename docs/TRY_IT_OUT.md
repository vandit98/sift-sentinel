# Try-It-Out Instructions

## Local Demo

Requirements:

- Python 3.9 or newer
- No external Python packages

Run:

```bash
PYTHONPATH=src python3 -m sift_sentinel benchmark \
  --case cases/demo-case/case.json \
  --run-id judge-demo \
  --max-iterations 3
```

Open:

- `cases/demo-case/outputs/judge-demo/reports/triage_report.md`
- `cases/demo-case/outputs/judge-demo/reports/accuracy_report.md`
- `cases/demo-case/outputs/judge-demo/analysis/execution_log.jsonl`

## MCP Server

Run the stdio MCP server:

```bash
PYTHONPATH=src python3 -m sift_sentinel mcp
```

Claude Desktop-style configuration example:

```json
{
  "mcpServers": {
    "sift-sentinel": {
      "command": "python3",
      "args": ["-m", "sift_sentinel", "mcp"],
      "env": {
        "PYTHONPATH": "/absolute/path/to/sift-sentinel/src"
      }
    }
  }
}
```

## SIFT Workstation

On SIFT:

1. Install Protocol SIFT from the hackathon instructions.
2. Clone this repo.
3. Put case evidence under `cases/<case-name>/evidence`.
4. Create a `case.json` that maps artifact names to parsed SIFT outputs.
5. Run the benchmark command above.

For raw images, extend `sift_sentinel.sift_wrappers` with the relevant typed wrapper. The existing wrappers show the pattern for Volatility 3 and EvtxECmd.

