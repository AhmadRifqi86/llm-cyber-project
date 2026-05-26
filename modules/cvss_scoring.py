import re
import os
import json
import math
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# CVSS v3.1 base score calculation
# ---------------------------------------------------------------------------

_AV = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20}
_AC = {'L': 0.77, 'H': 0.44}
_PR_U = {'N': 0.85, 'L': 0.62, 'H': 0.27}
_PR_C = {'N': 0.85, 'L': 0.68, 'H': 0.50}
_UI = {'N': 0.85, 'R': 0.62}
_CIA = {'N': 0.0, 'L': 0.22, 'H': 0.56}


def _roundup(value: float) -> float:
    """CVSS 'Roundup' – round up to nearest 0.1."""
    return math.ceil(value * 10) / 10


def calculate_cvss_base_score(metrics: Dict) -> float:
    """Calculate CVSS v3.1 base score from a metric dictionary."""
    try:
        S = metrics.get('S', 'U')
        AV = _AV.get(metrics.get('AV', 'N'), 0.85)
        AC = _AC.get(metrics.get('AC', 'L'), 0.77)
        PR = (_PR_C if S == 'C' else _PR_U).get(metrics.get('PR', 'N'), 0.85)
        UI = _UI.get(metrics.get('UI', 'N'), 0.85)
        C  = _CIA.get(metrics.get('C', 'N'), 0.0)
        I  = _CIA.get(metrics.get('I', 'N'), 0.0)
        A  = _CIA.get(metrics.get('A', 'N'), 0.0)

        isc_base = 1 - (1 - C) * (1 - I) * (1 - A)

        if S == 'U':
            iss = 6.42 * isc_base
        else:
            iss = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)

        exploitability = 8.22 * AV * AC * PR * UI

        if iss <= 0:
            return 0.0

        if S == 'U':
            raw = min(iss + exploitability, 10)
        else:
            raw = min(1.08 * (iss + exploitability), 10)

        return _roundup(raw)
    except Exception as e:
        print(f"CVSS calculation error: {e}")
        return 0.0


def get_severity_label(score: float) -> str:
    if score == 0.0:
        return 'None'
    elif score <= 3.9:
        return 'Low'
    elif score <= 6.9:
        return 'Medium'
    elif score <= 8.9:
        return 'High'
    return 'Critical'


# ---------------------------------------------------------------------------
# RAG-enhanced LLM scorer
# ---------------------------------------------------------------------------

class CVSSScorer:
    """CVSS base score generation using RAG + LLM (OpenAI-compatible API)."""

    def __init__(self, api_key: str = "", model: str = "local",
                 embedding_model: str = "all-MiniLM-L6-v2",
                 dataset_path: str = "data/cvss_dataset.csv",
                 index_path: str = "data/faiss_index",
                 base_url: str = None,
                 provider: str = "local"):
        self.api_key = api_key
        self.model = model
        self.embedding_model = embedding_model
        self.dataset_path = dataset_path
        self.index_path = index_path
        self.base_url = base_url
        self.provider = provider
        self.vector_store = None
        self._setup_rag()

    # ------------------------------------------------------------------
    def _setup_rag(self):
        """Build or load the FAISS vector store for RAG context retrieval."""
        try:
            from langchain_community.vectorstores import FAISS
            try:
                from langchain_core.documents import Document
            except ImportError:
                from langchain.schema import Document
            import pandas as pd
            from modules.utils import make_embeddings

            embeddings = make_embeddings(self.embedding_model, self.provider, self.api_key)

            if os.path.exists(self.index_path):
                try:
                    self.vector_store = FAISS.load_local(
                        self.index_path, embeddings,
                        allow_dangerous_deserialization=True
                    )
                    print("[#] Loaded existing FAISS index for RAG.")
                    return
                except Exception:
                    # Index built with different embedding dimension – rebuild
                    import shutil
                    shutil.rmtree(self.index_path, ignore_errors=True)
                    print("[!] Existing FAISS index incompatible (embedding changed). Rebuilding.")

            if not os.path.exists(self.dataset_path):
                print(f"[!] CVSS dataset not found at {self.dataset_path}. RAG disabled.")
                return

            df = pd.read_csv(self.dataset_path).dropna(subset=['description', 'cvss_vector'])
            docs = [
                Document(page_content=row['description'],
                         metadata={'cvss_vector': row['cvss_vector']})
                for _, row in df.iterrows()
            ]
            if not docs:
                print("[!] No valid rows in CVSS dataset.")
                return

            self.vector_store = FAISS.from_documents(docs, embeddings)
            os.makedirs(self.index_path, exist_ok=True)
            self.vector_store.save_local(self.index_path)
            print(f"[#] Created FAISS index with {len(docs)} CVSS examples.")

        except ImportError as e:
            print(f"[!] RAG dependencies missing ({e}). RAG context disabled.")
        except Exception as e:
            print(f"[!] RAG setup error: {e}")

    # ------------------------------------------------------------------
    def _llm_call(self, prompt: str, max_tokens: int = 200) -> str:
        """Send a prompt to the OpenAI-compatible LLM and return the response."""
        from modules.utils import make_llm_client
        client = make_llm_client(self.api_key, self.base_url)
        try:
            response = client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens,
                temperature=0.2,
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            print(f"LLM call error: {e}")
            return ""

    # ------------------------------------------------------------------
    def generate_vulnerability_description(self, vuln_type: str, scan_snippet: str) -> str:
        """LLM Prompt 1 – generate a 30-word impact-focused description."""
        prompt = f"""**Ensure description contains impact details so CVSS metrics will not default to 0.0**
You are a web application vulnerability detection expert tasked with analyzing vulnerability assessment scan data/results and generating a vulnerability description.
- Vulnerability type: {vuln_type}
- Scan results: {scan_snippet[:600]}

Generate a concise vulnerability description (max 30 words) that:
- Explains how the vulnerability can be exploited
- Describes likely impact (confidentiality, integrity, availability, or user compromise)

Examples:
- SQL Injection in the login parameter allows attackers to extract or modify sensitive data, leading to unauthorized access.
- Reflected XSS in the search field enables script injection, potentially hijacking sessions and exposing user data.

**Do not copy examples directly.**
**Ensure description contains impact details so CVSS metrics will not default to 0.0**"""
        desc = self._llm_call(prompt, max_tokens=80)
        if not desc:
            desc = f"{vuln_type} vulnerability enables attackers to compromise application confidentiality or integrity."
        return desc

    # ------------------------------------------------------------------
    def determine_cvss_metrics(self, description: str) -> Dict:
        """LLM Prompt 2 (RAG) – determine CVSS v3.1 metric values."""
        context = ""
        if self.vector_store:
            try:
                docs = self.vector_store.similarity_search(description, k=3)
                context = "\n".join(
                    f"Description: {d.page_content}\nCVSS Vector: {d.metadata.get('cvss_vector', '')}"
                    for d in docs
                )
            except Exception as e:
                print(f"RAG retrieval error: {e}")

        prompt = f"""You are a CVSS v3.1 scoring expert.
Below are relevant vulnerabilities and their official CVSS vectors:
{context}
New vulnerability description:
"{description}"

Instructions:
1. Determine the appropriate CVSS v3.1 metrics (AV, AC, PR, UI, S, C, I, A) **based on the description and your reasoning**.

2. Only generate the CVSS vector in valid JSON dictionary format like this:
{{"AV": "...", "AC": "...", "PR": "...", "UI": "...", "S": "...", "C": "...", "I": "...", "A": "..."}}

3. Rules for metrics:
- AV: N | A | L | P
- AC: H | L
- PR: N | L | H
- UI: N | R
- S: U | C
- C, I, A: N | L | H
- Do NOT set C, I, and A all to "N" if the description implies any impact. At least one must be "L" or "H".

4. Use your reasoning **internally**, do not just blindly copy from the retrieved examples.

5. Always output valid JSON with double quotes."""

        raw = self._llm_call(prompt, max_tokens=200)
        from modules.utils import try_parse_json
        parsed = try_parse_json(raw)
        if isinstance(parsed, dict) and 'AV' in parsed:
            return parsed
        return {"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                "S": "U", "C": "L", "I": "L", "A": "N"}

    # ------------------------------------------------------------------
    def score_vulnerability(self, vuln_type: str, scan_snippet: str) -> Dict:
        """Full pipeline: description → metrics → CVSS base score."""
        description = self.generate_vulnerability_description(vuln_type, scan_snippet)
        metrics = self.determine_cvss_metrics(description)
        score = calculate_cvss_base_score(metrics)
        severity = get_severity_label(score)
        return {
            'vulnerability_type': vuln_type,
            'description': description,
            'metrics': metrics,
            'score': score,
            'severity': severity,
        }

    # ------------------------------------------------------------------
    def score_all_vulnerabilities(self, va_results: Dict) -> Dict[str, float]:
        """Score every detected vulnerability and return {name: cvss_score}."""
        base_scores: Dict[str, float] = {}

        for domain, scans in va_results.items():
            # Directory traversal
            if scans.get('directory_traversal', {}).get('results'):
                r = self.score_vulnerability(
                    'Directory Path Traversal',
                    scans['directory_traversal']['raw']
                )
                base_scores['Directory Path Traversal'] = r['score']
                print(f"  [CVSS] Directory Path Traversal: {r['score']} ({r['severity']})")

            # XSS from PwnXSS
            if scans.get('xss', {}).get('results'):
                r = self.score_vulnerability('XSS', scans['xss']['raw'])
                base_scores['XSS'] = r['score']
                print(f"  [CVSS] XSS: {r['score']} ({r['severity']})")

            # Nikto (server misconfiguration)
            if scans.get('nikto', {}).get('raw', '').strip():
                r = self.score_vulnerability(
                    'Dangerous file info, outdated http headers, Server misconfiguration',
                    scans['nikto']['raw']
                )
                base_scores['Dangerous file info, outdated http headers, Server misconfiguration'] = r['score']
                print(f"  [CVSS] Server Misconfiguration: {r['score']} ({r['severity']})")

            # Weak cipher (testssl)
            if scans.get('weak_cipher', {}).get('results'):
                r = self.score_vulnerability('Weak Cipher', scans['weak_cipher']['raw'])
                base_scores['Weak Cipher'] = r['score']
                print(f"  [CVSS] Weak Cipher: {r['score']} ({r['severity']})")

            # Wapiti findings
            for vuln in scans.get('wapiti', []):
                vtype = vuln.get('header', 'Unknown')
                if vtype not in base_scores:
                    r = self.score_vulnerability(vtype, vuln.get('body', ''))
                    base_scores[vtype] = r['score']
                    print(f"  [CVSS] {vtype}: {r['score']} ({r['severity']})")

        return base_scores
