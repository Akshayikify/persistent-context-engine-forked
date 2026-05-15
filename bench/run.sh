#!/bin/bash
# Anvil P-02 Benchmark Runner
set -e

# Path to the adapter
ADAPTER="adapters.mine:Engine"

echo "🚀 Starting Persistent Context Engine Benchmark..."

# Run the standard seeds (L2 Evaluation)
# This emits the JSON report required by the SDK schema
python3 run.py \
    --adapter "$ADAPTER" \
    --mode fast \
    --seeds 42 101 202 303 404 \
    --out report.json

echo "✅ Benchmark complete. Report saved to report.json"

# Print a summary to stdout for the judges
python3 -c "
import json
with open('report.json') as f:
    r = json.load(f)
    agg = r['aggregated']
    print(f'\n--- FINAL METRICS ---')
    print(f'Recall@5:         {agg[\"recall@5\"]}')
    print(f'Precision:         {agg[\"precision@5_mean\"]}')
    print(f'Remediation Acc:   {agg[\"remediation_acc\"]}')
    print(f'p95 Latency:       {agg[\"latency_p95_ms\"]}ms')
    print(f'---------------------\n')
"
