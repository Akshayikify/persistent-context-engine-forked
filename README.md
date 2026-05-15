# Anvil P-02: Persistent Context Engine (PCE)

This engine is a high-performance, **Pure Python (stdlib-only)** solution for the ANVIL P-02 problem statement. It identifies recurring incident patterns in distributed systems while remaining robust against **Topology Drift** (service renames and dependency shifts).

## 🏆 Final Benchmark Results
*Tested against the official P-02 Context Harness (L2 Evaluation)*

| Metric | Score | Target |
| :--- | :--- | :--- |
| **Recall@5** | **1.000** | > 0.85 (Perfect) |
| **Precision** | **0.852** | > 0.50 (Excellent) |
| **Remediation Acc** | **1.000** | > 0.90 (Perfect) |
| **Latency (p95)** | **13.6ms** | < 2000ms (150x faster) |

---

## 🏗️ Technical Architecture & Defense

### 1. Temporal Identity Resolver (Topology Drift)
The PCE handles **Cascading Rename Chains** (e.g., `svc-01` → `svc-01-r4` → `svc-01-r7`) using a recursive forward-alias mapping logic.
- **How it works**: Every ingested event is normalized to its "Canonical Identity" at query time. This ensures that a training incident from last month matches a current incident even if the service name has morphed.

### 2. Native Causal Graph (Graph & Relationships)
Instead of simple keyword matching, we built a native **Directed Causal Graph** using standard Python `dict` objects.
- **Edge Synthesis**: We automatically link Trace Spans (RPC links), Deployment-to-Anomaly impacts, and Error-to-Signal triggers.
- **Backwards BFS Traversal**: The engine performs a real-time traversal from the failure signal back to the originating root cause (Deployment).

### 3. Behavioral Fingerprinting & Learning (Memory Evolution)
- **Topology-Independent Signatures**: Incidents are grouped by their "Behavioral DNA" (N-gram trigger analysis and Kind Distributions) rather than strings.
- **Reinforcement Tally**: The engine tracks the historical success/failure ratios of remediation actions. It **learns** which fixes work for which fingerprints over time.

---

## 👥 Team Assignments & Ownership
- **Jaya Sai**: Data & Identity Architect (Alias Resolution & Normalize Logic)
- **Akshay H**: Graph Engineer (Causal Edge Synthesis & BFS Traversal)
- **Pratham**: Lead (Behavioral Fingerprinting & Reinforcement Learning)

---

## 🚀 Quickstart

### Reproducibility
The project is containerized for easy evaluation:
```powershell
docker build -t anvil-pce .
docker run anvil-pce
```

### Manual Benchmarking
To run the automated self-check:
```powershell
python self_check.py --adapter adapters.mine:Engine
```

To run a custom stress test:
```powershell
python run.py --adapter adapters.mine:Engine --seeds 9999 31415 27182 --n-services 20 --days 14
```

## 📝 Compliance Statement
- **100% Pure Python**: No external dependencies (no NetworkX, no Polars).
- **Stdlib Only**: Compatible with standard Python 3.8+ environments.
