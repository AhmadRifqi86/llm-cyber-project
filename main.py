#!/usr/bin/env python3
"""
Automated Web Application Penetration Testing Framework
Based on the methodology proposed in:
  "Automating Web Application Vulnerability Detection:
   A Generative AI and Security Tool Based Penetration Testing Framework"
   (Brac University, October 2025)

Pipeline:
  1. Reconnaissance   – crt.sh, Subfinder, Nmap, wafw00f, Wappalyzer, ParamSpider
  2. Vulnerability Assessment – Gobuster, PwnXSS, Nikto, testssl.sh, Wapiti
  3. Action Plan Generation   – LLM (OpenAI-compatible)
  4. CVSS Scoring             – RAG (FAISS) + LLM → CVSS v3.1
  5. Overall Security Score   – normalization + power transform + aggregation
  6. Report Generation        – LLM HTML report

Usage:
    python main.py <domain> [--api-key KEY] [--model MODEL] [--output-dir DIR]
    python main.py <domain> --skip-recon --skip-vuln   # LLM/scoring only (demo)
"""

import os
import sys
import json
import argparse
from datetime import datetime

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Automated Web Application Penetration Testing Framework"
    )
    p.add_argument("domain", help="Target domain (e.g. example.com)")
    p.add_argument(
        "--api-key",
        default=os.environ.get("OPENAI_API_KEY", ""),
        help="OpenAI API key (or set OPENAI_API_KEY env var)"
    )
    p.add_argument(
        "--model", default="gpt-4o",
        help="LLM model to use (default: gpt-4o)"
    )
    p.add_argument(
        "--output-dir", default="output",
        help="Base output directory (default: output)"
    )
    p.add_argument(
        "--skip-recon", action="store_true",
        help="Skip reconnaissance phase (load from file if available)"
    )
    p.add_argument(
        "--skip-vuln", action="store_true",
        help="Skip vulnerability assessment (load from file if available)"
    )
    p.add_argument(
        "--skip-llm", action="store_true",
        help="Skip LLM steps (action plan, CVSS, report)"
    )
    p.add_argument(
        "--lambda-val", type=float, default=1.5,
        help="Power-transform lambda for security scoring (default: 1.5)"
    )
    return p


def load_json_if_exists(path: str, default):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return default


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    if not args.api_key and not args.skip_llm:
        print(
            "ERROR: OpenAI API key required for LLM steps.\n"
            "  Set OPENAI_API_KEY environment variable or use --api-key KEY\n"
            "  To skip LLM steps use --skip-llm"
        )
        sys.exit(1)

    # Create timestamped output directory
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.join(args.output_dir, f"scan_{args.domain}_{ts}")
    os.makedirs(out_dir, exist_ok=True)

    print("=" * 65)
    print("  Automated Penetration Testing Framework")
    print(f"  Target : {args.domain}")
    print(f"  Model  : {args.model}")
    print(f"  Output : {out_dir}")
    print("=" * 65)

    from modules.reconnaissance import run_reconnaissance
    from modules.vulnerability_assessment import run_vulnerability_assessment
    from modules.cvss_scoring import CVSSScorer
    from modules.security_scoring import calculate_overall_security_score
    from modules.action_plan import generate_action_plan
    from modules.report_generation import generate_report
    from modules.utils import save_json

    # ------------------------------------------------------------------ #
    # 1. Reconnaissance                                                    #
    # ------------------------------------------------------------------ #
    recon_cache = os.path.join(out_dir, "recon_results.json")
    if args.skip_recon:
        recon_info = load_json_if_exists(recon_cache, {
            'domain': args.domain,
            'active_subdomains': [args.domain],
            'unique_ips': [],
            'ip_addresses': {},
            'open_ports': {},
            'tech_stack': {},
            'firewall': 'skipped',
            'ssl_tls': [False, 'skipped'],
            'parameters': 'skipped',
        })
        print("[!] Reconnaissance phase skipped.")
    else:
        recon_info = run_reconnaissance(args.domain, out_dir)
        save_json(recon_info, recon_cache)

    ssl_supported = (recon_info.get('ssl_tls') or [False])[0]
    active_subs = recon_info.get('active_subdomains') or [args.domain]

    # ------------------------------------------------------------------ #
    # 2. Vulnerability Assessment                                          #
    # ------------------------------------------------------------------ #
    vuln_cache = os.path.join(out_dir, "vulnerability_results.json")
    if args.skip_vuln:
        va_results = load_json_if_exists(vuln_cache, {})
        print("[!] Vulnerability assessment phase skipped.")
    else:
        va_results = run_vulnerability_assessment(
            args.domain, active_subs, ssl_supported, out_dir
        )
        save_json(va_results, vuln_cache)

    if args.skip_llm:
        print("\n[!] LLM steps skipped (--skip-llm).")
        print(f"\nResults saved to: {out_dir}")
        return

    # ------------------------------------------------------------------ #
    # 3. Action Plan (LLM)                                                 #
    # ------------------------------------------------------------------ #
    action_plan = generate_action_plan(
        recon_info, va_results,
        api_key=args.api_key, model=args.model, output_dir=out_dir
    )

    # ------------------------------------------------------------------ #
    # 4. CVSS Scoring (RAG + LLM)                                          #
    # ------------------------------------------------------------------ #
    print("\n[#] Generating CVSS base scores...")
    scorer = CVSSScorer(
        api_key=args.api_key,
        model=args.model,
        dataset_path="data/cvss_dataset.csv",
        index_path="data/faiss_index",
    )
    base_scores = scorer.score_all_vulnerabilities(va_results)
    print(f"\nBase scores dict: {base_scores}")
    save_json(base_scores, os.path.join(out_dir, "base_scores.json"))

    # ------------------------------------------------------------------ #
    # 5. Overall System Security Score                                     #
    # ------------------------------------------------------------------ #
    print("\n[#] Calculating overall system security score...")
    security_score = calculate_overall_security_score(
        base_scores, lambda_val=args.lambda_val
    )
    save_json(security_score, os.path.join(out_dir, "security_score.json"))

    # ------------------------------------------------------------------ #
    # 6. HTML Report (LLM)                                                 #
    # ------------------------------------------------------------------ #
    generate_report(
        recon_info, va_results, base_scores, security_score,
        api_key=args.api_key, model=args.model, output_dir=out_dir
    )

    # ------------------------------------------------------------------ #
    # Summary                                                              #
    # ------------------------------------------------------------------ #
    print("\n" + "=" * 65)
    print("  Penetration Testing Complete")
    print(f"  Results saved to : {out_dir}")
    print(f"  Security Score   : {security_score.get('score', 'N/A')} / 100")
    print(f"  Security Rating  : {security_score.get('rating', 'N/A')}")
    print("=" * 65)


if __name__ == "__main__":
    main()
