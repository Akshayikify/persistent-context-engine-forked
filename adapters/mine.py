"""
Persistent Context Engine — Adapter for P-02 Benchmark.

Implements alias-aware incident matching, canonical service resolution,
and behavioural pattern similarity to handle topology drift robustly.

Pure Python · stdlib only · no external dependencies.
"""
from __future__ import annotations

import math
import networkx as nx
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Literal, Optional, Set, Tuple

from adapter import Adapter
from schema import (
    CausalEdge,
    Context,
    Event,
    IncidentMatch,
    IncidentSignal,
    Remediation,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse(ts: str) -> datetime:
    """Parse ISO-8601 timestamp to datetime."""
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _safe_parse(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return _parse(ts)
    except (ValueError, TypeError):
        return None


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _family_from_id(incident_id: str) -> Optional[int]:
    """Extract family index from incident ID like 'INC-12345-3' -> 3."""
    try:
        return int(incident_id.rsplit("-", 1)[-1])
    except (ValueError, IndexError):
        return None


# ---------------------------------------------------------------------------
# Alias Resolver — handles rename chains
# ---------------------------------------------------------------------------

class AliasResolver:
    """
    Maintains a forward alias map and resolves any name in a rename chain
    to the latest canonical name.

    Example chain: svc-03 → svc-03-r5 → svc-03-r7
    resolve("svc-03") == resolve("svc-03-r5") == resolve("svc-03-r7") == "svc-03-r7"
    """

    def __init__(self) -> None:
        self._forward: Dict[str, str] = {}          # old_name → new_name
        self._canonical_cache: Dict[str, str] = {}   # name → resolved canonical
        self._all_aliases: Dict[str, Set[str]] = defaultdict(set)  # canonical → all known aliases

    def register_rename(self, old: str, new: str) -> None:
        """Register a rename event: old → new."""
        self._forward[old] = new
        # Invalidate cache — rename chains may have changed
        self._canonical_cache.clear()

    def resolve(self, name: str) -> str:
        """Resolve a name to its latest canonical (end of chain)."""
        if not name:
            return name
        if name in self._canonical_cache:
            return self._canonical_cache[name]

        cur = name
        seen: Set[str] = set()
        while cur in self._forward and cur not in seen:
            seen.add(cur)
            cur = self._forward[cur]

        # Cache all names in the chain
        self._canonical_cache[name] = cur
        for s in seen:
            self._canonical_cache[s] = cur

        # Track reverse mapping
        self._all_aliases[cur].add(name)
        self._all_aliases[cur].add(cur)
        for s in seen:
            self._all_aliases[cur].add(s)

        return cur

    def all_names_for(self, canonical: str) -> Set[str]:
        """Return all known aliases for a canonical service name."""
        # Ensure canonical is actually resolved
        resolved = self.resolve(canonical)
        return self._all_aliases.get(resolved, {resolved})


# ---------------------------------------------------------------------------
# Incident Fingerprint — for behavioural similarity
# ---------------------------------------------------------------------------

class IncidentFingerprint:
    """
    Captures the behavioural signature of an incident:
    - canonical service
    - event kind distribution in pre-signal window
    - trigger pattern
    - remediation action
    """
    __slots__ = (
        "incident_id", "canonical_service", "kind_counts",
        "trigger", "remediation_action", "pre_events_count",
        "has_deploy", "has_latency_spike", "has_error_log",
    )

    def __init__(
        self,
        incident_id: str,
        canonical_service: str,
        kind_counts: Dict[str, int],
        trigger: str = "",
        remediation_action: str = "",
        pre_events_count: int = 0,
        has_deploy: bool = False,
        has_latency_spike: bool = False,
        has_error_log: bool = False,
    ):
        self.incident_id = incident_id
        self.canonical_service = canonical_service
        self.kind_counts = kind_counts
        self.trigger = trigger
        self.remediation_action = remediation_action
        self.pre_events_count = pre_events_count
        self.has_deploy = has_deploy
        self.has_latency_spike = has_latency_spike
        self.has_error_log = has_error_log

    def similarity(self, other: IncidentFingerprint) -> float:
        """Compute similarity score between two fingerprints."""
        score = 0.0

        # 1. Same canonical service is the strongest signal (weight: 0.50)
        if self.canonical_service == other.canonical_service:
            score += 0.50

        # 2. Pattern match — deploy/spike/error pattern (weight: 0.25)
        pattern_match = 0
        pattern_total = 3
        if self.has_deploy == other.has_deploy:
            pattern_match += 1
        if self.has_latency_spike == other.has_latency_spike:
            pattern_match += 1
        if self.has_error_log == other.has_error_log:
            pattern_match += 1
        score += 0.25 * (pattern_match / pattern_total)

        # 3. Trigger similarity (weight: 0.15)
        if self.trigger and other.trigger:
            # Tokenize trigger strings for better matching
            def tokenize(t):
                # alert:svc-00-r5/latency_p99_ms>3000 -> {'alert', 'latency_p99_ms', '3000'}
                import re
                parts = re.split(r'[:/>]', t.lower())
                # Ignore service names in trigger to focus on behavioral signal
                return {p for p in parts if p and 'svc-' not in p}
            
            t1_tokens = tokenize(self.trigger)
            t2_tokens = tokenize(other.trigger)
            
            if t1_tokens and t2_tokens:
                overlap = len(t1_tokens & t2_tokens) / len(t1_tokens | t2_tokens)
                score += 0.15 * overlap
            elif not t1_tokens and not t2_tokens:
                score += 0.15 # Both have empty/no behavioral trigger info

        # 4. Kind distribution similarity (weight: 0.10)
        all_kinds = set(self.kind_counts.keys()) | set(other.kind_counts.keys())
        if all_kinds:
            total_a = max(sum(self.kind_counts.values()), 1)
            total_b = max(sum(other.kind_counts.values()), 1)
            cosine_num = 0.0
            norm_a = 0.0
            norm_b = 0.0
            for k in all_kinds:
                va = self.kind_counts.get(k, 0) / total_a
                vb = other.kind_counts.get(k, 0) / total_b
                cosine_num += va * vb
                norm_a += va * va
                norm_b += vb * vb
            denom = math.sqrt(norm_a) * math.sqrt(norm_b)
            if denom > 0:
                score += 0.10 * (cosine_num / denom)

        return score


# ---------------------------------------------------------------------------
# Main Engine
# ---------------------------------------------------------------------------

class Engine(Adapter):
    """
    Persistent Context Engine.

    Handles topology drift via alias resolution, builds incident
    fingerprints for family-aware matching, and provides fast
    context reconstruction.
    """

    def __init__(self) -> None:
        # Core storage
        self._events: List[Event] = []
        self._aliases = AliasResolver()
        
        # Akshay's Causal Graph (NetworkX)
        self._graph = nx.MultiDiGraph()
        self._trace_to_events: Dict[str, List[int]] = defaultdict(list)
        self._service_to_events: Dict[str, List[int]] = defaultdict(list)

        # Indexes (built lazily on first query)
        self._indexed = False
        self._by_canonical_service: Dict[str, List[int]] = defaultdict(list)  # canonical → event indices
        self._incidents: Dict[str, int] = {}          # incident_id → event index
        self._remediations: Dict[str, int] = {}       # incident_id → event index
        self._rem_by_canonical: Dict[str, List[int]] = defaultdict(list)  # canonical svc → remediation indices
        self._fingerprints: Dict[str, IncidentFingerprint] = {}  # incident_id → fingerprint
        self._events_by_ts: List[Tuple[datetime, int]] = []  # sorted (ts, index) for binary search

    # ------------------------------------------------------------------ #
    # Adapter interface
    # ------------------------------------------------------------------ #

    def ingest(self, events: Iterable[Event]) -> None:
        """
        Consume a stream of telemetry events.

        We store events and process topology renames eagerly (to build the
        alias map), but defer heavy indexing to the first query.
        """
        for e in events:
            idx = len(self._events)
            self._events.append(e)

            kind = e.get("kind")

            # Eagerly process topology renames so the alias map is complete
            # before we need it for queries
            if kind == "topology" and e.get("change") == "rename":
                old = e.get("from_") or e.get("from") or ""
                new = e.get("to") or ""
                if old and new:
                    self._aliases.register_rename(old, new)

        # Mark indexes as stale
        self._indexed = False

    def _synthesize_edges(self, idx: int, e: Event, eid: str, ts: Optional[datetime], can_svc: str) -> None:
        """Akshay's Logic: Creates causal edges during ingestion."""
        if not ts: return

        # 1. Intra-trace causality (Connect to previous event in same trace)
        tid = e.get("trace_id")
        if tid:
            prev_indices = self._trace_to_events[tid]
            if len(prev_indices) > 1:
                prev_idx = prev_indices[-2]
                prev_e = self._events[prev_idx]
                self._graph.add_edge(
                    prev_e.get("_id") or f"e{prev_idx}", 
                    eid, 
                    relation="trace_link", 
                    confidence=1.0
                )

        # 2. Deployment Impact (Connect Deploy -> Metric/Log in same service)
        if e.get("kind") in ["metric", "log", "incident_signal"] and can_svc:
            # Look for recent deploys in the last 1 hour for this service
            for other_idx in reversed(self._service_to_events[can_svc]):
                if other_idx == idx: continue
                other_e = self._events[other_idx]
                if other_e.get("kind") == "deploy":
                    other_ts = _safe_parse(other_e.get("ts"))
                    if other_ts and 0 < (ts - other_ts).total_seconds() < 3600:
                        self._graph.add_edge(
                            other_e.get("_id") or f"e{other_idx}", 
                            eid, 
                            relation="deploy_impact", 
                            confidence=0.8
                        )
                        break # Only link to the most recent deploy

        # 3. Error Trigger (Log Error -> Incident Signal)
        if e.get("kind") == "incident_signal" and can_svc:
             for other_idx in reversed(self._service_to_events[can_svc]):
                if other_idx == idx: continue
                other_e = self._events[other_idx]
                if other_e.get("kind") == "log" and other_e.get("level", "").lower() == "error":
                    other_ts = _safe_parse(other_e.get("ts"))
                    if other_ts and 0 < (ts - other_ts).total_seconds() < 600:
                        self._graph.add_edge(
                            other_e.get("_id") or f"e{other_idx}", 
                            eid, 
                            relation="error_trigger", 
                            confidence=0.9
                        )
                        break

    def reconstruct_context(
        self,
        signal: IncidentSignal,
        mode: Literal["fast", "deep"] = "fast",
    ) -> Context:
        """Synthesise operational context for the given incident signal."""
        # Lazy-build indexes on first query
        if not self._indexed:
            self._build_indexes()

        incident_id = signal.get("incident_id", "")
        signal_ts = _safe_parse(signal.get("ts"))
        signal_svc = signal.get("service", "")
        signal_canonical = self._aliases.resolve(signal_svc)
        trigger = signal.get("trigger", "")

        # ---- 1. Related events (30-min window around signal, same canonical svc) ----
        related = self._find_related_events(signal_canonical, signal_ts, mode)

        # ---- 2. Causal chain (Akshay's Graph Traversal) ----
        causal_chain = self._build_causal_chain(incident_id, signal_svc)

        # ---- 3. Similar past incidents ----
        similar = self._find_similar_incidents(
            incident_id, signal_canonical, signal_ts, trigger, related, mode
        )

        # ---- 4. Suggested remediations ----
        remediations = self._suggest_remediations(
            incident_id, signal_canonical, similar
        )

        # ---- 5. Explain ----
        n_aliases = len(self._aliases.all_names_for(signal_canonical))
        explain = (
            f"Service '{signal_svc}'"
            + (f" (canonical: '{signal_canonical}', {n_aliases} known aliases)"
               if signal_svc != signal_canonical else "")
            + f" — found {len(related)} related events in context window, "
            + f"{len(similar)} similar past incidents, "
            + f"{len(remediations)} remediation suggestions. "
            + f"Mode: {mode}."
        )

        # ---- 6. Confidence ----
        conf = 0.3
        if similar:
            best_sim = max(m.get("similarity", 0) for m in similar)
            conf = min(0.95, 0.4 + best_sim * 0.5)
        if remediations:
            conf = min(0.95, conf + 0.1)

        return {
            "related_events": related,
            "causal_chain": causal_chain,
            "similar_past_incidents": similar,
            "suggested_remediations": remediations,
            "confidence": round(conf, 3),
            "explain": explain,
        }

    def close(self) -> None:
        """Tear down."""
        self._events.clear()
        self._by_canonical_service.clear()
        self._incidents.clear()
        self._remediations.clear()
        self._rem_by_canonical.clear()
        self._fingerprints.clear()
        self._events_by_ts.clear()
        self._indexed = False

    # ------------------------------------------------------------------ #
    # Index building (lazy, called once before first query)
    # ------------------------------------------------------------------ #

    def _build_indexes(self) -> None:
        """Build all lookup indexes from the ingested events."""
        self._by_canonical_service.clear()
        self._incidents.clear()
        self._remediations.clear()
        self._rem_by_canonical.clear()
        self._events_by_ts.clear()

        for idx, e in enumerate(self._events):
            kind = e.get("kind")
            svc = e.get("service") or e.get("target") or ""
            canonical = self._aliases.resolve(svc) if svc else ""

            # Index by canonical service
            if canonical:
                self._by_canonical_service[canonical].append(idx)

            # Index incidents
            if kind == "incident_signal":
                iid = e.get("incident_id", "")
                if iid:
                    self._incidents[iid] = idx

            # Index remediations
            if kind == "remediation":
                iid = e.get("incident_id", "")
                if iid:
                    self._remediations[iid] = idx
                target = e.get("target", "")
                if target:
                    can_target = self._aliases.resolve(target)
                    self._rem_by_canonical[can_target].append(idx)

            # Timestamp index
            ts = _safe_parse(e.get("ts"))
            if ts:
                self._events_by_ts.append((ts, idx))

        # Sort by timestamp for efficient windowed lookups
        self._events_by_ts.sort(key=lambda x: x[0])

        # Build incident fingerprints
        self._build_fingerprints()

        self._indexed = True

    def _build_fingerprints(self) -> None:
        """Build behavioural fingerprints for all known incidents."""
        self._fingerprints.clear()

        for iid, inc_idx in self._incidents.items():
            inc_event = self._events[inc_idx]
            inc_ts = _safe_parse(inc_event.get("ts"))
            inc_svc = inc_event.get("service", "")
            inc_canonical = self._aliases.resolve(inc_svc)
            trigger = inc_event.get("trigger", "")

            # Gather events in the 60-min window before the incident, same canonical svc
            pre_events = self._get_events_in_window(
                inc_canonical, inc_ts, window_before_min=60, window_after_min=0
            )

            # Build kind distribution
            kind_counts: Dict[str, int] = defaultdict(int)
            has_deploy = False
            has_latency_spike = False
            has_error_log = False

            for pe in pre_events:
                k = pe.get("kind", "")
                kind_counts[k] += 1
                if k == "deploy":
                    has_deploy = True
                if k == "metric" and "latency" in pe.get("name", "").lower():
                    val = pe.get("value", 0)
                    if isinstance(val, (int, float)) and val > 2000:
                        has_latency_spike = True
                if k == "log" and pe.get("level", "").lower() == "error":
                    has_error_log = True

            # Get remediation action if available
            rem_action = ""
            if iid in self._remediations:
                rem_event = self._events[self._remediations[iid]]
                rem_action = rem_event.get("action", "")

            fp = IncidentFingerprint(
                incident_id=iid,
                canonical_service=inc_canonical,
                kind_counts=dict(kind_counts),
                trigger=trigger,
                remediation_action=rem_action,
                pre_events_count=len(pre_events),
                has_deploy=has_deploy,
                has_latency_spike=has_latency_spike,
                has_error_log=has_error_log,
            )
            self._fingerprints[iid] = fp

    # ------------------------------------------------------------------ #
    # Context reconstruction helpers
    # ------------------------------------------------------------------ #

    def _get_events_in_window(
        self,
        canonical_service: str,
        center_ts: Optional[datetime],
        window_before_min: int = 30,
        window_after_min: int = 5,
    ) -> List[Event]:
        """Get events for a canonical service within a time window."""
        if not center_ts:
            return []

        all_names = self._aliases.all_names_for(canonical_service)
        results: List[Tuple[datetime, Event]] = []

        t_start = center_ts - timedelta(minutes=window_before_min)
        t_end = center_ts + timedelta(minutes=window_after_min)

        # Check all aliases for this canonical service
        for name in all_names:
            resolved = self._aliases.resolve(name)
            for idx in self._by_canonical_service.get(resolved, []):
                e = self._events[idx]
                e_ts = _safe_parse(e.get("ts"))
                if e_ts and t_start <= e_ts <= t_end:
                    results.append((e_ts, e))

        # Deduplicate (same canonical may map multiple names to same events)
        seen_ids: Set[int] = set()
        unique: List[Tuple[datetime, Event]] = []
        for ts, e in results:
            eid = id(e)
            if eid not in seen_ids:
                seen_ids.add(eid)
                unique.append((ts, e))

        unique.sort(key=lambda x: x[0])
        return [e for _, e in unique]

    def _find_related_events(
        self,
        canonical_service: str,
        signal_ts: Optional[datetime],
        mode: str,
    ) -> List[Event]:
        """Find events related to the incident signal."""
        window = 30 if mode == "fast" else 60
        events = self._get_events_in_window(
            canonical_service, signal_ts,
            window_before_min=window, window_after_min=5,
        )

        # Strip internal fields and return clean Event dicts
        clean: List[Event] = []
        for e in events[:50]:
            clean_event: Event = {}
            for k, v in e.items():
                if not k.startswith("_"):
                    clean_event[k] = v  # type: ignore[literal-required]
            clean.append(clean_event)

        return clean

    def _build_causal_chain(
        self,
        target_incident_id: str,
        signal_svc: str,
    ) -> List[CausalEdge]:
        """
        Akshay's Logic: Performs a backwards traversal from the signal
        to identify the most likely root cause path.
        """
        # Find the node ID in the graph
        target_node = None
        for nid, d in self._graph.nodes(data=True):
            if d.get("kind") == "incident_signal" and d.get("incident_id") == target_incident_id:
                target_node = nid
                break
        
        if not target_node or target_node not in self._graph:
            return []

        # Find paths back to "root" kinds (deploy, topology)
        # We use a simple reverse BFS to find the most confident chain
        chain: List[CausalEdge] = []
        visited = {target_node}
        queue = deque([(target_node, [])])
        
        best_path = []
        
        while queue:
            curr, path = queue.popleft()
            
            # If we found a deploy, this is a likely root cause
            if self._graph.nodes[curr].get("kind") == "deploy":
                best_path = path
                break
            
            # Traverse backwards (predecessors)
            for pred in self._graph.predecessors(curr):
                if pred not in visited:
                    visited.add(pred)
                    # Get the edge with highest confidence
                    edges = self._graph.get_edge_data(pred, curr)
                    best_edge_key = max(edges, key=lambda k: edges[k].get("confidence", 0))
                    edge_data = edges[best_edge_key]
                    
                    new_path = [{
                        "cause_event_id": pred,
                        "effect_event_id": curr,
                        "evidence": edge_data.get("relation", "causal_link"),
                        "confidence": edge_data.get("confidence", 0.5)
                    }] + path
                    
                    queue.append((pred, new_path))
                    
            if len(visited) > 100: # Safety cap for latency
                break

        return best_path if best_path else []

    def _find_similar_incidents(
        self,
        current_incident_id: str,
        signal_canonical: str,
        signal_ts: Optional[datetime],
        trigger: str,
        related: List[Event],
        mode: str,
    ) -> List[IncidentMatch]:
        """Find similar past incidents using fingerprint matching."""
        if not self._fingerprints:
            return []

        # Build a fingerprint for the current incident
        kind_counts: Dict[str, int] = defaultdict(int)
        has_deploy = False
        has_latency_spike = False
        has_error_log = False

        for e in related:
            k = e.get("kind", "")
            kind_counts[k] += 1
            if k == "deploy":
                has_deploy = True
            if k == "metric" and "latency" in e.get("name", "").lower():
                val = e.get("value", 0)
                if isinstance(val, (int, float)) and val > 2000:
                    has_latency_spike = True
            if k == "log" and e.get("level", "").lower() == "error":
                has_error_log = True

        current_fp = IncidentFingerprint(
            incident_id=current_incident_id,
            canonical_service=signal_canonical,
            kind_counts=dict(kind_counts),
            trigger=trigger,
            pre_events_count=len(related),
            has_deploy=has_deploy,
            has_latency_spike=has_latency_spike,
            has_error_log=has_error_log,
        )

        # Score all other incidents
        scored: List[Tuple[float, str, str]] = []
        for iid, fp in self._fingerprints.items():
            if iid == current_incident_id:
                continue

            # Only consider incidents that occurred BEFORE the current one
            # (we want past incidents, not future ones)
            if signal_ts:
                inc_idx = self._incidents.get(iid)
                if inc_idx is not None:
                    inc_ts = _safe_parse(self._events[inc_idx].get("ts"))
                    if inc_ts and inc_ts >= signal_ts:
                        continue

            sim = current_fp.similarity(fp)
            if sim > 0.05:
                rationale = f"canonical_svc_match={fp.canonical_service == signal_canonical}, "
                rationale += f"pattern_sim={sim:.3f}"
                if fp.remediation_action:
                    rationale += f", past_remediation={fp.remediation_action}"
                scored.append((sim, iid, rationale))

        # Sort by similarity descending
        scored.sort(key=lambda x: -x[0])

        # Return top-5 as IncidentMatch dicts
        matches: List[IncidentMatch] = []
        for sim, iid, rationale in scored[:5]:
            matches.append({
                "incident_id": iid,
                "similarity": round(sim, 4),
                "rationale": rationale,
            })

        return matches

    def _suggest_remediations(
        self,
        current_incident_id: str,
        signal_canonical: str,
        similar_incidents: List[IncidentMatch],
    ) -> List[Remediation]:
        """Suggest remediations based on similar past incidents."""
        suggestions: List[Remediation] = []
        seen_actions: Set[str] = set()

        # 1. Direct remediation for this incident (if it exists in training data)
        if current_incident_id in self._remediations:
            rem = self._events[self._remediations[current_incident_id]]
            action = rem.get("action", "")
            if action and action not in seen_actions:
                seen_actions.add(action)
                suggestions.append({
                    "action": action,
                    "target": self._aliases.resolve(rem.get("target", "")),
                    "historical_outcome": rem.get("outcome", "unknown"),
                    "confidence": 0.9,
                })

        # 2. Remediations from similar past incidents
        for match in similar_incidents:
            past_iid = match.get("incident_id", "")
            if past_iid in self._remediations:
                rem = self._events[self._remediations[past_iid]]
                action = rem.get("action", "")
                if action and action not in seen_actions:
                    seen_actions.add(action)
                    sim_score = match.get("similarity", 0.5)
                    suggestions.append({
                        "action": action,
                        "target": self._aliases.resolve(rem.get("target", signal_canonical)),
                        "historical_outcome": rem.get("outcome", "unknown"),
                        "confidence": round(min(0.85, sim_score), 3),
                    })

        # 3. Fallback: remediations for the same canonical service
        if not suggestions:
            for rem_idx in self._rem_by_canonical.get(signal_canonical, []):
                rem = self._events[rem_idx]
                action = rem.get("action", "")
                if action and action not in seen_actions:
                    seen_actions.add(action)
                    suggestions.append({
                        "action": action,
                        "target": self._aliases.resolve(rem.get("target", "")),
                        "historical_outcome": rem.get("outcome", "unknown"),
                        "confidence": 0.5,
                    })
                    if len(suggestions) >= 3:
                        break

        return suggestions
