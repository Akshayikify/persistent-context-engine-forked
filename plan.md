Project: Persistent Context Engine (P2) — Hackathon MVP

Goal

Build a lightweight operational memory engine that ingests JSONL telemetry, synthesizes dynamic relationships across events (no fixed schema), and reconstructs investigation context robust to topology drift (renames, dependency changes).

MVP Scope (24h)

- Ingest: JSONL pipeline (deploy, log, metric, trace, topology, remediation) + provenance and replay.
- Memory store: temporal graph (events as nodes, relationships as edges) with basic decay and indexing.
- Similarity & rename robustness: simple canonicalization (aliases) + embedding + nearest-neighbor matching for past incidents.
- reconstruct_context(signal, mode): fast mode returns related_events, causal_chain (simple causality heuristics), similar_past_incidents, suggested_remediations, confidence, explain.
- Bench adapter: implement adapters/myteam.py to satisfy harness interface; integrate self_check quick runs.
- Demo: 3 worked incident scenarios & a short demo script.

Success Metrics

- Ingest latency: event → queryable ≤ 5s (L2 goal)
- reconstruct_context (fast) p95 ≤ 2s
- Similar-past recall@5 ≥ baseline (bench will score)
- Reproducible demo: Docker/run script that executes the scenario and outputs a JSON report

Team roles (3 people)

- ML/Alg: similarity, embeddings, causal heuristics, evaluation metrics
- Backend: ingest pipeline, graph store, bench adapter, API
- Frontend/DevOps: small UI for demo, Docker + reproducibility, demo script

24‑hour schedule (recommended)

- Hour 0 (planning) — finalize 3 incidents, dataset subset, assign tasks (30m)
- Hours 1–4 (core infra) — ingest pipeline, basic graph store, bench adapter skeleton (3.5h)
- Hours 4–8 (algorithms) — implement similarity & rename-robust matching, quick index (4h)
- Hours 8–12 (reconstruct API) — implement fast mode, causal_edge heuristics, run self_check quick (4h)
- Hours 12–18 (polish) — demo script, dashboard, packaging, Docker (6h)
- Hours 18–24 (test + writeup) — run full seeds, fix regressions, write 3‑page defense, record demo (6h)

Immediate next actions

1. Prepare or extract a small JSONL sample (1–2k events) and 3 incident signals.
2. Implement adapters/myteam.py skeleton and run `python self_check.py --quick` to confirm harness integration.
3. Build ingest → graph store → reconstruct_context fast path.

Notes

- Keep components minimal and deterministic for judges: avoid external APIs.
- Use SQLite or in‑memory structures to stay reproducible; optimize only if needed.
- Log provenance IDs for every relationship to make explainable causal chains.

Deliverables

- adapters/myteam.py implementing ingest/reconstruct_context/close
- demo script + Dockerfile
- 3‑page writeup + README

