import sys
from core.logger import init_db, create_run, finalize_run
from core.reporter import generate_html_report
from core.config import MODEL, ATTACKS
from attacks.prompt_injection import run as run_prompt_injection
from attacks.jailbreak import run as run_jailbreak
from attacks.indirect_injection import run as run_indirect_injection

def banner():
    print("""
╔══════════════════════════════════════════╗
║         LLM Red-Team Framework           ║
║      github.com/SriramVallabhaneni       ║
╚══════════════════════════════════════════╝
    """)

def main():
    banner()

    print(f"[*] Target model: {MODEL}")
    print(f"[*] Initializing database...")
    init_db()

    run_id = create_run(MODEL)
    print(f"[*] Started run #{run_id}\n")

    results = {}

    if ATTACKS.get("prompt_injection"):
        results["prompt_injection"] = run_prompt_injection(run_id)

    if ATTACKS.get("jailbreak"):
        results["jailbreak"] = run_jailbreak(run_id)

    if ATTACKS.get("indirect_injection"):
        results["indirect_injection"] = run_indirect_injection(run_id)

    print("\n[*] Finalizing run...")
    finalize_run(run_id)

    print("[*] Generating report...")
    report_path = generate_html_report(run_id)

    # Print final summary
    total = sum(len(v) for v in results.values() if v is not None)
    succeeded = sum(
        sum(1 for r in v if r.get("success"))
        for v in results.values()
        if v is not None
    )

    print(f"""
╔══════════════════════════════════════════╗
║              Run Complete                ║
╠══════════════════════════════════════════╣
║  Total tests:     {str(total).ljust(23)}║
║  Succeeded:       {str(succeeded).ljust(23)}║
║  Resisted:        {str(total - succeeded).ljust(23)}║
╚══════════════════════════════════════════╝

Report: {report_path}
    """)

if __name__ == "__main__":
    main()