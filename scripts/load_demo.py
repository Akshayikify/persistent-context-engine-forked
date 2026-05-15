import sys
from pathlib import Path

# Add project root to sys.path so we can import 'adapters'
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from adapters.myteam import Engine
if __name__ == '__main__':
    e = Engine()
    path = r'C:\SRE\demo_data\demo_2k.jsonl'
    n = e.load_from_file(path)
    print(f'Loaded {n} events into engine. Total stored: {len(e.events)}')
    
    # load incidents
    inc_path = r'C:\SRE\demo_data\incidents_demo.jsonl'
    m = e.load_from_file(inc_path)
    print(f'Loaded {m} incident signals. Total stored: {len(e.events)}')
    
    # Run acceptance tests
    print("\n--- Acceptance Tests ---")
    inc_count = sum(1 for ev in e.events if ev.get('kind')=='incident_signal')
    print(f"Incident nodes count: {inc_count}")
    if e.graph:
        print(f"Graph size: {e.graph.number_of_nodes()} nodes, {e.graph.number_of_edges()} edges")
    
    demo_incidents = ['INC-101', 'INC-202', 'INC-303']
    for inc_id in demo_incidents:
        inc_node = next((ev for ev in e.events if ev.get('incident_id') == inc_id), None)
        if not inc_node:
            print(f"\nCould not find incident {inc_id} in loaded data.")
            continue
            
        print(f"\n==============================")
        print(f"Evaluating incident: {inc_id}")
        print(f"==============================")
        
        # Fast mode
        ctx_fast = e.reconstruct_context(inc_node, mode='fast')
        print(f"Fast Mode (hops=2) - Related count: {len(ctx_fast['related_events'])}")
        for r in ctx_fast['related_events'][:5]:
            print(f"  {r['_id']} | score: {r.get('_score', 0):.4f} | {r.get('service')} | {r.get('ts')}")
            
        # Deep mode
        ctx_deep = e.reconstruct_context(inc_node, mode='deep')
        print(f"\nDeep Mode (hops=3) - Related count: {len(ctx_deep['related_events'])}")
        for r in ctx_deep['related_events'][:5]:
            print(f"  {r['_id']} | score: {r.get('_score', 0):.4f} | {r.get('service')} | {r.get('ts')}")
            
        print("\nExplanation (Deep):")
        print("  " + ctx_deep['explain'])
        print("Similar Past Incidents (Top 3):")
        for sim in ctx_deep.get('similar_past_incidents', [])[:3]:
            print(f"  {sim['past_incident_id']} | sim: {sim['similarity']:.3f} | {sim['rationale']}")

