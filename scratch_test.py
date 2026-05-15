import json
from adapters.mine import Engine

sample_jsonl = """
{"ts":"2026-05-10T14:21:30Z","kind":"deploy",  "service":"payments-svc","version":"v2.14.0","actor":"ci"}
{"ts":"2026-05-10T14:22:01Z","kind":"log",     "service":"checkout-api","level":"error","msg":"timeout calling payments-svc","trace_id":"abc123"}
{"ts":"2026-05-10T14:22:01Z","kind":"metric",  "service":"payments-svc","name":"latency_p99_ms","value":4820}
{"ts":"2026-05-10T14:22:08Z","kind":"trace",   "trace_id":"abc123","spans":[{"svc":"checkout-api","dur_ms":5012},{"svc":"payments-svc","dur_ms":4980}]}
{"ts":"2026-05-10T14:30:00Z","kind":"topology","change":"rename","from":"payments-svc","to":"billing-svc"}
{"ts":"2026-05-10T14:32:11Z","kind":"incident_signal","incident_id":"INC-714","trigger":"alert:checkout-api/error-rate>5%","service":"checkout-api"}
{"ts":"2026-05-10T15:10:00Z","kind":"remediation","incident_id":"INC-714","action":"rollback","target":"billing-svc","version":"v2.13.4","outcome":"resolved"}
"""

events = [json.loads(line) for line in sample_jsonl.strip().split("\n")]

# Extract the incident signal
signal = None
for e in events:
    if e["kind"] == "incident_signal":
        signal = e
        break

engine = Engine()
engine.ingest(events)

context = engine.reconstruct_context(signal)

print(json.dumps(context, indent=2, default=str))
