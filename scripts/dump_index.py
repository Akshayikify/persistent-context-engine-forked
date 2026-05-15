import os
import sys

# Add parent directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from adapters.myteam import Engine

if __name__ == "__main__":
    e = Engine()
    e.load_from_file(r'C:\SRE\demo_data\demo_2k.jsonl')
    e.load_from_file(r'C:\SRE\demo_data\incidents_demo.jsonl')
    
    print("\n--- Incident Index Dump ---")
    print(f"Total entries: {len(e.incident_index)}")
    print(f"Top Services used for vector: {e.top_services[:10]}...")
    
    for idx in e.incident_index[:5]:
        vec_str = ", ".join(f"{x:.3f}" for x in idx['vector'][:10]) + "..."
        print(f"Incident: {idx['incident_id']}")
        print(f"  Services: {list(idx['services'])}")
        print(f"  Kinds: {dict(idx['kinds'])}")
        print(f"  Vector prefix: [{vec_str}]")
        print("-" * 30)
