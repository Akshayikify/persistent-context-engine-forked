"""
PCE Verification Tool: Family & Signal Diagnostic
Compares matched incident families with ground truth to guarantee they are
True Positives (no false classification across families).
"""
import sys
import os
from pathlib import Path

# Ensure import paths work locally
sys.path.insert(0, os.getcwd())

from generator import GenConfig, generate
from adapters.mine import Engine
from metrics import _family_from_incident_id

def run_diagnostic():
    # Use standard test configuration
    cfg = GenConfig(seed=42, n_services=12, days=7)
    dataset = generate(cfg)
    
    # Initialize Engine and Ingest data
    engine = Engine()
    # Join train events and evaluation telemetry together
    engine.ingest(dataset.train_events + dataset.eval_events)
    
    print("\n================================================================")
    print(" PCE GROUND-TRUTH FAMILY VERIFICATION")
    print("================================================================\n")
    print(f"Loaded dataset with {len(dataset.train_events)} training events.")
    print(f"Running analysis on {len(dataset.eval_signals)} evaluation signals.\n")

    total_returned = 0
    true_positives = 0
    false_positives = 0

    # Evaluate the first 8 evaluation incident signals
    for signal in dataset.eval_signals[:8]:
        eval_id = signal["incident_id"]
        eval_family = _family_from_incident_id(eval_id)
        eval_svc = signal["service"]
        
        # Perform context reconstruction
        ctx = engine.reconstruct_context(signal, mode="fast")
        similar = ctx.get("similar_past_incidents", [])

        print(f"-> Testing Incident: {eval_id} (Service: {eval_svc})")
        print(f"   Ground Truth Family ID: [ {eval_family} ]")
        
        if not similar:
            print("   [!] No similar past incidents returned.")
        else:
            for rank, match in enumerate(similar[:3]): # View Top-3 similar
                match_id = match["incident_id"]
                match_fam = _family_from_incident_id(match_id)
                sim_score = match["similarity"]
                
                # Verify match
                is_correct = (eval_family == match_fam)
                total_returned += 1
                if is_correct:
                    true_positives += 1
                    outcome_str = "[OK] TRUE POSITIVE (Correct Match)"
                else:
                    false_positives += 1
                    outcome_str = "[FAIL] FALSE POSITIVE (Mismatched Family)"
                
                print(f"   |- [{rank+1}] Match ID: {match_id} (Family: {match_fam})")
                print(f"   |   Similarity Score: {sim_score:.3f}  -->  {outcome_str}")
        print("-" * 64)

    # Print Summary
    if total_returned > 0:
        precision = (true_positives / total_returned) * 100
        print(f"\nDIAGNOSTIC SUMMARY:")
        print(f"   - Total Evaluated Matches: {total_returned}")
        print(f"   - True Positives:          {true_positives}")
        print(f"   - False Positives:         {false_positives}")
        print(f"   - Match Precision Accuracy: {precision:.1f}%\n")
    else:
        print("\n[!] No matches evaluated.")

if __name__ == "__main__":
    run_diagnostic()
