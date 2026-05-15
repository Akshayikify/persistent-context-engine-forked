# Persistent Context Engine (PCE) Documentation

## Overview
The Persistent Context Engine (PCE) is a streaming graph-based system designed for autonomous SRE and observability. It transforms raw telemetry into a continuously evolving operational memory graph, enabling real-time causal analysis and incident context reconstruction.

## Key Concepts

### 1. Streaming Graph Construction
Unlike traditional systems that batch-process data, PCE builds its causal graph **online** as events arrive.
- **Nodes**: Every telemetry event (log, metric, deploy, etc.) becomes a node.
- **Edges**: Relationships are synthesized immediately using local neighborhood reasoning.

### 2. Causal Synthesis Heuristics
PCE uses temporal and semantic heuristics to infer causality:
- **Deployment Impact**: A `deploy` followed by a `metric` spike in the same service within 5 minutes.
- **Resource Exhaustion**: High latency (`metric`) followed by `timeout` or `error` (`log`).
- **Error Trigger**: An error `log` followed by an `incident_signal`.

### 3. Incremental Topology Learning
The system learns service dependencies dynamically from `trace` events.
- **Trace Spans**: If a trace shows `Service A -> Service B`, a dependency relationship is established.
- **Topology Drift**: PCE handles service renames (via `topology` events) using an alias resolution map, ensuring causal continuity.

### 4. Causal Chain Traversal
When an incident is detected, PCE traverses the graph backwards from the incident signal to find likely root causes (e.g., a recent deployment or a topology change).
- **Confidence Scoring**: Each edge has a confidence score (0.0 - 1.0) based on the heuristic strength and temporal proximity.

## Module: `graph.py`

### `CausalGraph` Class
The main engine implementing the PCE logic.

#### Core Methods:
- `ingest_event(event)`: The primary entry point for streaming data.
- `reconstruct_local_context(event_id)`: Generates a high-level summary of the operational neighborhood around an event.
- `find_causal_chains(target_id)`: Identifies paths from root causes to a target event.
- `get_related_events(event_id)`: Finds all events in the graph neighborhood within a certain depth.

## Event Schema
Events are provided as dictionaries with the following recommended fields:
- `event_id`: Unique identifier.
- `ts`: ISO 8601 timestamp.
- `kind`: `deploy`, `log`, `metric`, `trace`, `topology`, `remediation`, `incident_signal`.
- `service`: Name of the service generating the event.
- `trace_id`: (Optional) For linking events in a request flow.
- `spans`: (For traces) List of service interactions.

## Performance Optimization
- **Sliding Window**: PCE maintains a configurable sliding temporal window (default 60 minutes) of recent events in memory. This ensures that edge synthesis remains O(1) or O(N_local) rather than O(N_total).
- **NetworkX MultiDiGraph**: Provides a robust foundation for multi-relational directed graphs.
