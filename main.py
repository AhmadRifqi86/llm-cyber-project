#!/usr/bin/env python3
"""
Automated Web Application Penetration Testing Framework
Based on the methodology proposed in:
  "Automating Web Application Vulnerability Detection:
   A Generative AI and Security Tool Based Penetration Testing Framework"
   (Brac University, October 2025)

Pipeline:
  1. Reconnaissance        – crt.sh, Subfinder, Nmap, wafw00f, Wappalyzer, ParamSpider
  2. Vulnerability Assessment – Gobuster, PwnXSS, Nikto, testssl.sh, Wapiti
  3. Exploit Phase          – LLM-planned + automated exploit execution (sqlmap + custom)
  4. Action Plan            – LLM manual action plan
  5. CVSS Scoring           – RAG (FAISS) + LLM → CVSS v3.1
  6. Overall Security Score – normalization + power transform + aggregation
  7. Report Generation      – LLM HTML report (includes exploit PoC evidence)

Local LLM (default):
    # Start llama.cpp server first, then:
    python main.py example.com

OpenAI:
    LLM_PROVIDER=openai OPENAI_API_KEY=sk-... python main.py example.com

Other options:
    python main.py example.com --skip-recon --skip-vuln
    python main.py example.com --skip-exploit
    python main.py example.com --skip-llm
"""

import os
import sys
import json
import argparse
from datetime import datetime

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from config import LLM_PROVIDER, LLM_BASE_URL, LLM_MODEL, EMBEDDING_MODEL, OPENAI_API_KEY


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Automated Web Application Penetration Testing Framework"
    )
    p.add_argument("domain", help="Target domain (e.g. example.com)")
    p.add_argument(
        "--api-key",
        default=OPENAI_API_KEY,
        help="API key (required only when LLM_PROVIDER=openai)"
    )
    p.add_argument(
        "--base-url",
        default=LLM_BASE_URL,
        help=f"LLM server base URL (default: {LLM_BASE_URL})"
    )
    p.add_argument(
        "--model", default=LLM_MODEL,
        help=f"LLM model name (default: {LLM_MODEL})"
    )
    p.add_argument(
        "--provider", default=LLM_PROVIDER,
        choices=["local", "openai"],
        help=f"LLM provider (default: {LLM_PROVIDER})"
    )
    p.add_argument(
        "--output-dir", default="output",
        help="Base output directory (default: output)"
    )
    p.add_argument(
        "--skip-recon", action="store_true",
        help="Skip reconnaissance phase (load from cache if available)"
    )
    p.add_argument(
        "--skip-vuln", action="store_true",
        help="Skip vulnerability assessment (load from cache if available)"
    )
    p.add_argument(
        "--skip-exploit", action="store_true",
        help="Skip automated exploit phase"
    )
    p.add_argument(
        "--skip-llm", action="store_true",
        help="Skip all LLM steps (action plan, CVSS, scoring, report)"
    )
    p.add_argument(
        "--lambda-val", type=float, default=1.5,
        help="Power-transform lambda for security scoring (default: 1.5)"
    )
    p.add_argument(
        "--force-llm", action="store_true",
        help="Skip known-app fast path and force the generic LLM-based exploit loop"
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

    # Normalize target: accept full URLs, host:port, or bare domains
    from urllib.parse import urlparse
    raw_target = args.domain
    if '://' not in raw_target:
        raw_target = 'http://' + raw_target
    _parsed = urlparse(raw_target)
    _host = _parsed.hostname or args.domain
    _port = _parsed.port
    # Preserve non-standard ports so tools hit the right port
    if _port and _port not in (80, 443):
        args.domain = f"{_host}:{_port}"
    else:
        args.domain = _host
    # Sanitize for use in directory names (colons, slashes, etc.)
    _safe_domain = args.domain.replace(':', '_').replace('/', '_')

    # Validate API key requirement
    if not args.skip_llm:
        if args.provider == "openai" and not args.api_key:
            print(
                "ERROR: OpenAI API key required when LLM_PROVIDER=openai.\n"
                "  Set OPENAI_API_KEY env var or pass --api-key KEY\n"
                "  For a local LLM use --provider local (default)"
            )
            sys.exit(1)
        if args.provider == "local" and not args.api_key:
            args.api_key = "local"   # llama.cpp / Ollama accept any non-empty key

    # Create timestamped output directory
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.join(args.output_dir, f"scan_{_safe_domain}_{ts}")
    os.makedirs(out_dir, exist_ok=True)

    print("=" * 65)
    print("  Automated Penetration Testing Framework")
    print(f"  Target   : {args.domain}")
    print(f"  Provider : {args.provider}")
    print(f"  LLM URL  : {args.base_url}")
    print(f"  Model    : {args.model}")
    print(f"  Output   : {out_dir}")
    print("=" * 65)

    from modules.reconnaissance import run_reconnaissance
    from modules.vulnerability_assessment import run_vulnerability_assessment
    from modules.exploit import run_exploit_phase
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

    # Discover additional web services on other open ports
    from modules.reconnaissance import discover_web_ports
    extra_targets = discover_web_ports(recon_info, args.domain)
    for t in extra_targets:
        if t not in active_subs:
            active_subs.append(t)
    if extra_targets:
        print(f"[+] Added {len(extra_targets)} extra web target(s) from open ports: {extra_targets}")

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
    # 3. Exploit Phase                                                     #
    # ------------------------------------------------------------------ #
    exploit_cache = os.path.join(out_dir, "exploit_results.json")
    if args.skip_exploit:
        exploit_results = load_json_if_exists(exploit_cache, {})
        print("[!] Exploit phase skipped.")
    else:
        exploit_results = run_exploit_phase(
            domain=args.domain,
            recon_info=recon_info,
            va_results=va_results,
            api_key=args.api_key,
            model=args.model,
            base_url=args.base_url,
            output_dir=out_dir,
            force_llm=args.force_llm,
        )
        save_json(exploit_results, exploit_cache)

    # ------------------------------------------------------------------ #
    # 4. Action Plan (LLM)                                                 #
    # ------------------------------------------------------------------ #
    generate_action_plan(
        recon_info, va_results,
        api_key=args.api_key, model=args.model,
        output_dir=out_dir, base_url=args.base_url,
    )

    # ------------------------------------------------------------------ #
    # 5. CVSS Scoring (RAG + LLM)                                          #
    # ------------------------------------------------------------------ #
    print("\n[#] Generating CVSS base scores...")
    scorer = CVSSScorer(
        api_key=args.api_key,
        model=args.model,
        embedding_model=EMBEDDING_MODEL,
        dataset_path="data/cvss_dataset.csv",
        index_path="data/faiss_index",
        base_url=args.base_url,
        provider=args.provider,
    )
    base_scores = scorer.score_all_vulnerabilities(va_results)
    print(f"\nBase scores: {base_scores}")
    save_json(base_scores, os.path.join(out_dir, "base_scores.json"))

    # ------------------------------------------------------------------ #
    # 6. Overall System Security Score                                     #
    # ------------------------------------------------------------------ #
    print("\n[#] Calculating overall system security score...")
    security_score = calculate_overall_security_score(
        base_scores, lambda_val=args.lambda_val
    )
    save_json(security_score, os.path.join(out_dir, "security_score.json"))

    # ------------------------------------------------------------------ #
    # 7. HTML Report (LLM)                                                 #
    # ------------------------------------------------------------------ #
    generate_report(
        recon_info, va_results, base_scores, security_score,
        api_key=args.api_key, model=args.model,
        output_dir=out_dir, base_url=args.base_url,
        exploit_results=exploit_results if not args.skip_exploit else None,
    )

    # ------------------------------------------------------------------ #
    # Summary                                                              #
    # ------------------------------------------------------------------ #
    print("\n" + "=" * 65)
    print("  Penetration Testing Complete")
    print(f"  Results saved to  : {out_dir}")
    print(f"  Security Score    : {security_score.get('score', 'N/A')} / 100")
    print(f"  Security Rating   : {security_score.get('rating', 'N/A')}")
    if not args.skip_exploit and exploit_results:
        s = exploit_results.get('summary', {})
        print(f"  Exploits run      : {s.get('total', 0)}")
        print(f"  Confirmed vulns   : {s.get('vulnerable', 0)}")
    print("=" * 65)


if __name__ == "__main__":
    main()
