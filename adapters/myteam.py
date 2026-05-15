import json
import os
import math
import networkx as nx
from typing import Iterable, Dict, List, Optional, Tuple
from datetime import datetime, timezone
from collections import Counter

ISO_FMT = '%Y-%m-%dT%H:%M:%SZ'

def parse_ts(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.strptime(ts, ISO_FMT).replace(tzinfo=timezone.utc)
    except Exception:
        try:
            return datetime.fromisoformat(ts)
        except Exception:
            return None

def cosine_sim(a: List[float], b: List[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    num = sum(x*y for x,y in zip(a,b))
    na = math.sqrt(sum(x*x for x in a))
    nb = math.sqrt(sum(y*y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return num / (na * nb)

class Engine:
    """Adapter engine with alias resolution, weighted graph traversal, and incident similarity indexing."""
    def __init__(self):
        self.events: List[Dict] = []
        self.aliases: Dict[str,str] = {}
        self._next_id = 1
        self.graph: Optional[nx.DiGraph] = None
        # tuning params
        self.default_hops = 3
        self.time_window_seconds = 48 * 3600  # 48 hours for related events
        self.distance_decay = 0.8  # per-hop multiplicative decay
        self.max_results = 100
        # similarity index
        self.top_services: List[str] = []
        self.incident_index: List[Dict] = []  # list of {'incident_id','vector','services','kinds'}
        self.svc_weight = 2.0
        # fingerprinting locality params
        self.fingerprint_hops = 1
        self.fingerprint_window_seconds = 2 * 3600
        self.fingerprint_top_k = 25

    def ingest(self, events: Iterable[Dict]) -> None:
        for e in events:
            self._add_event(e, provenance=None)
        self.build_graph()

    def load_from_file(self, path: str) -> int:
        if not os.path.exists(path):
            raise FileNotFoundError(f"Path not found: {path}")
        loaded = 0
        with open(path, 'r', encoding='utf-8') as f:
            for i, raw in enumerate(f, start=1):
                line = raw.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                prov = {'__source': os.path.abspath(path), '__line': i}
                self._add_event(obj, provenance=prov)
                loaded += 1
        self.build_graph()
        return loaded

    def _add_event(self, event: Dict, provenance: Dict = None) -> None:
        e = dict(event)
        if '_id' not in e:
            e['_id'] = f"e{self._next_id}"
            self._next_id += 1
        if provenance is not None:
            e.setdefault('_provenance', provenance)
        self.events.append(e)

    def _resolve_alias_chain(self, name: str) -> str:
        if not name:
            return name
        cur = name
        seen = set()
        while cur in self.aliases and cur not in seen:
            seen.add(cur)
            cur = self.aliases[cur]
        return cur

    def build_graph(self) -> None:
        G = nx.DiGraph()
        # First pass: collect renames ordered by timestamp to build alias mapping
        rename_events = [e for e in self.events if e.get('kind') == 'topology' and e.get('change') == 'rename']
        rename_events_sorted = sorted(rename_events, key=lambda x: x.get('ts', ''))
        for r in rename_events_sorted:
            frm = r.get('from')
            to = r.get('to')
            if frm and to:
                for k, v in list(self.aliases.items()):
                    if v == frm:
                        self.aliases[k] = to
                self.aliases[frm] = to
        # Second pass: add nodes with canonicalized service names
        service_counter = Counter()
        for e in self.events:
            e['_ts_parsed'] = parse_ts(e.get('ts'))
            svc = e.get('service')
            if svc:
                can = self._resolve_alias_chain(svc)
                e['_service_canonical'] = can
                service_counter[can] += 1
            else:
                e['_service_canonical'] = None
            G.add_node(e['_id'], **e)
        # decide top services for fingerprinting
        self.top_services = [s for s, _ in service_counter.most_common(50)]
        # trace edges
        trace_map = {}
        for e in self.events:
            tid = e.get('trace_id')
            if not tid:
                continue
            trace_map.setdefault(tid, []).append(e)
        for tid, evs in trace_map.items():
            evs_sorted = sorted(evs, key=lambda x: x.get('ts', ''))
            for a, b in zip(evs_sorted, evs_sorted[1:]):
                w = self._edge_weight_for_time_delta(a.get('ts'), b.get('ts'))
                G.add_edge(a['_id'], b['_id'], type='trace', weight=w)
        # provenance edges
        for e in self.events:
            prov = e.get('_provenance')
            if prov:
                src = prov.get('__source')
                if src:
                    src_id = f"src:{os.path.basename(src)}"
                    if not G.has_node(src_id):
                        G.add_node(src_id, kind='source', path=src)
                    G.add_edge(src_id, e['_id'], type='provenance', weight=0.2)
        # service adjacency edges using canonical service names
        service_map = {}
        for e in self.events:
            svc = e.get('_service_canonical')
            if svc:
                service_map.setdefault(svc, []).append(e)
        for svc, evs in service_map.items():
            evs_sorted = sorted(evs, key=lambda x: x.get('ts', ''))
            for i, a in enumerate(evs_sorted):
                for b in evs_sorted[i+1:i+6]:
                    w = self._edge_weight_for_time_delta(a.get('ts'), b.get('ts')) * 0.9
                    G.add_edge(a['_id'], b['_id'], type='adjacent_service', weight=w)
        self.graph = G
        # build incident fingerprints/index
        self._build_incident_index()

    def _edge_weight_for_time_delta(self, t_from: Optional[str], t_to: Optional[str]) -> float:
        tf = parse_ts(t_from)
        tt = parse_ts(t_to)
        if tf and tt:
            dt = abs((tt - tf).total_seconds())
            tau = 3600.0
            w = max(0.05, math.exp(-dt / tau))
            return w
        return 0.5

    def _score_from_paths(self, source_node: str, target_node: str, max_hops: int) -> float:
        if self.graph is None:
            return 0.0
        if source_node == target_node:
            return 1.0
        score = 0.0
        visited = set([source_node])
        frontier = [(source_node, 0, 1.0)]
        # traverse both successors and predecessors to capture edges in both directions
        while frontier:
            node, depth, acc = frontier.pop(0)
            if depth >= max_hops:
                continue
            nbrs = list(self.graph.successors(node)) + list(self.graph.predecessors(node))
            for nbr in nbrs:
                edge = self.graph.get_edge_data(node, nbr) or self.graph.get_edge_data(nbr, node)
                if not edge:
                    continue
                w = edge.get('weight', 0.5) if isinstance(edge, dict) else 0.5
                new_acc = acc * w * (self.distance_decay ** depth)
                if nbr == target_node:
                    score += new_acc
                if nbr not in visited:
                    visited.add(nbr)
                    frontier.append((nbr, depth+1, new_acc))
        return score

    def events_by_incident(self, incident_id: str, hops: Optional[int] = None, time_window_seconds: Optional[int] = None, score_threshold: float = 1e-6) -> List[Dict]:
        if self.graph is None:
            return []
        hops = hops if hops is not None else self.default_hops
        time_window_seconds = time_window_seconds if time_window_seconds is not None else self.time_window_seconds
        incident_nodes = [n for n, d in self.graph.nodes(data=True) if d.get('kind') == 'incident_signal' and d.get('incident_id') == incident_id]
        if not incident_nodes:
            return []
        src = incident_nodes[0]
        src_ts = self.graph.nodes[src].get('_ts_parsed')
        scores = {}
        # restrict to neighborhood candidates to improve efficiency
        neighborhood = set()
        try:
            lengths = nx.single_source_shortest_path_length(self.graph.to_undirected(), src, cutoff=hops+2)
            neighborhood = set(lengths.keys())
        except Exception:
            neighborhood = set(self.graph.nodes())
        for n in neighborhood:
            d = self.graph.nodes[n]
            if not isinstance(d, dict) or d.get('_id') is None:
                continue
            if n == src:
                continue
            node_ts = d.get('_ts_parsed')
            if node_ts and src_ts:
                dt = abs((node_ts - src_ts).total_seconds())
                if dt > time_window_seconds:
                    continue
                recency_score = max(0.05, 1.0 - (dt / time_window_seconds))
            else:
                recency_score = 0.2
            path_score = self._score_from_paths(src, n, hops)
            total_score = path_score * recency_score
            if total_score >= score_threshold:
                scores[n] = total_score
        ranked = sorted(scores.items(), key=lambda kv: (-kv[1], self.graph.nodes[kv[0]].get('_ts_parsed') or datetime.min.replace(tzinfo=timezone.utc), kv[0]))
        results = []
        for node_id, sc in ranked[:self.max_results]:
            data = dict(self.graph.nodes[node_id])
            data['_score'] = sc
            results.append(data)
        return results

    def events_by_trace(self, trace_id: str) -> List[Dict]:
        if self.graph is None:
            return []
        nodes = [d for n, d in self.graph.nodes(data=True) if d.get('trace_id') == trace_id]
        return sorted(nodes, key=lambda x: x.get('ts', ''))

    def _build_incident_index(self) -> None:
        # build fingerprint vectors for every incident_signal node
        self.incident_index = []
        kinds = ['deploy','log','metric','trace','topology','remediation','incident_signal']
        for n, d in self.graph.nodes(data=True):
            if d.get('kind') != 'incident_signal':
                continue
            inc_id = d.get('incident_id')
            # gather local windowed events around the incident using tighter hops/window
            candidates = self.events_by_incident(inc_id, hops=self.fingerprint_hops, time_window_seconds=self.fingerprint_window_seconds)
            # if no local candidates, fallback to trace-based events (closer causal evidence)
            if not candidates:
                trace_id = d.get('trace_id')
                if trace_id:
                    candidates = self.events_by_trace(trace_id)
            top_k = candidates[:self.fingerprint_top_k]
            svc_counter = Counter((e.get('_service_canonical') or e.get('service')) for e in top_k if (e.get('_service_canonical') or e.get('service')))
            kind_counts = Counter(e.get('kind') for e in top_k if e.get('kind'))
            total = max(1, len(top_k))
            # vectorize: service counts normalized + kind counts normalized
            svc_vec = [svc_counter.get(s,0)/total for s in self.top_services]
            kind_vec = [kind_counts.get(k,0)/total for k in kinds]
            # apply service weighting
            svc_vec = [v * self.svc_weight for v in svc_vec]
            vec = svc_vec + kind_vec
            # L2 normalize
            norm = math.sqrt(sum(x*x for x in vec))
            if norm > 0:
                vec = [x / norm for x in vec]
            self.incident_index.append({'incident_id': inc_id, 'node': n, 'vector': vec, 'services': set(svc_counter.keys()), 'kinds': kind_counts})

    def _fingerprint_for_incident(self, incident_id: str) -> Optional[Dict]:
        if self.graph is None:
            return None
        candidates = self.events_by_incident(incident_id, hops=self.fingerprint_hops, time_window_seconds=self.fingerprint_window_seconds)
        # fallback to trace events if no local candidates
        if not candidates:
            # try to find incident node
            node = next((nid for nid, d in self.graph.nodes(data=True) if d.get('kind')=='incident_signal' and d.get('incident_id')==incident_id), None)
            if node:
                trace_id = self.graph.nodes[node].get('trace_id')
                if trace_id:
                    candidates = self.events_by_trace(trace_id)
        top_k = candidates[:self.fingerprint_top_k]
        svc_counter = Counter((e.get('_service_canonical') or e.get('service')) for e in top_k if (e.get('_service_canonical') or e.get('service')))
        kind_counts = Counter(e.get('kind') for e in top_k if e.get('kind'))
        total = max(1, len(top_k))
        svc_vec = [svc_counter.get(s,0)/total for s in self.top_services]
        kind_vec = [kind_counts.get(k,0)/total for k in ['deploy','log','metric','trace','topology','remediation','incident_signal']]
        svc_vec = [v * self.svc_weight for v in svc_vec]
        vec = svc_vec + kind_vec
        norm = math.sqrt(sum(x*x for x in vec))
        if norm > 0:
            vec = [x / norm for x in vec]
        return {'incident_id': incident_id, 'vector': vec, 'services': set(svc_counter.keys()), 'kinds': kind_counts}

    def reconstruct_context(self, signal: Dict, mode: str = 'fast') -> Dict:
        incident_id = signal.get('incident_id')
        trace_id = signal.get('trace_id')
        related = []
        if incident_id:
            related = self.events_by_incident(incident_id, hops=(self.default_hops if mode=='fast' else 4))
        elif trace_id:
            related = self.events_by_trace(trace_id)
        if not related:
            related = sorted(self.events, key=lambda x: x.get('ts', ''), reverse=True)[:20]
        causal_chain = []
        if trace_id and self.graph is not None:
            seq = self.events_by_trace(trace_id)
            for a, b in zip(seq, seq[1:]):
                causal_chain.append({'cause_id': a.get('_id'), 'effect_id': b.get('_id'), 'evidence': ['trace'], 'confidence': 0.6})
        similar = []
        if incident_id and self.graph is not None and related:
            target_services = { (e.get('_service_canonical') or e.get('service')) for e in related if (e.get('_service_canonical') or e.get('service')) }
            # simple graph-based similar incidents (service overlap)
            for entry in self.incident_index:
                if entry['incident_id'] == incident_id:
                    continue
                overlap = len(target_services & entry['services'])
                if overlap > 0:
                    similar.append({'past_incident_id': entry['incident_id'], 'similarity': overlap, 'rationale': f'{overlap} overlapping services'})
            # also compute vector similarity and include top-5
            fp = self._fingerprint_for_incident(incident_id)
            if fp:
                sims: List[Tuple[str,float,Dict]] = []
                for entry in self.incident_index:
                    if entry['incident_id'] == incident_id:
                        continue
                    score = cosine_sim(fp['vector'], entry['vector'])
                    if score > 0:
                        sims.append((entry['incident_id'], score, {'services': entry['services'], 'kinds': entry['kinds']}))
                sims_sorted = sorted(sims, key=lambda t: -t[1])[:5]
                # merge sims into similar list with cosine rationale
                for sid, sc, meta in sims_sorted:
                    similar.append({'past_incident_id': sid, 'similarity': float(sc), 'rationale': f'cosine={sc:.3f}; shared_services={len(target_services & meta["services"]) if meta.get("services") else 0}'})
        rems = [e for e in self.events if e.get('kind') == 'remediation' and e.get('incident_id') == incident_id]
        suggested = [{'action': r.get('action'), 'target': self._resolve_alias_chain(r.get('target')), 'historical_outcome': r.get('outcome'), 'confidence': 0.5} for r in rems]
        explain = f"Found {len(related)} related events (mode={mode}); {len(causal_chain)} causal edges; {len(similar)} similar past incidents."
        return {
            'related_events': related,
            'causal_chain': causal_chain,
            'similar_past_incidents': similar,
            'suggested_remediations': suggested,
            'confidence': 0.6,
            'explain': explain
        }

    def close(self) -> None:
        self.events.clear()
        self.graph = None
