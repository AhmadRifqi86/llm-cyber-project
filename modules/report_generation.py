import os
from typing import Dict


REPORT_PROMPT = """You are a cybersecurity expert tasked with analyzing reconnaissance and vulnerability assessment scan
data/results. The data below contains information about domains, their IP addresses, open ports, technology stack,
and other relevant details. Your task is to generate a report in HTML format following the fixed format provided below.

Here is the overall security rating of the web application:
- Security rating: {security_rating}
- Security score: {security_score} / 100

Here is the reconnaissance result:
{recon_info}

**Recon Report Format:**
1. **A Summary of the findings**
- Include numbers for each and every information provided in the reconnaissance result.
2. **Potential Targets**
- List of active domains and their IP addresses, excluding non-web services like mail, pop, smtp, FTP, or SSH
- The open ports of the respective IP addresses.
- Technologies of the main domain.
- Firewall/WAF detection.
- SSL/TLS Certification existence.

Here is the Vulnerability Scan Result:
{vuln_results}

Pre-calculated CVSS v3.1 Scores: {base_scores}

**Vulnerability Assessment Report Format:**
1. **Main Page Table**
- Generate a main page with a table containing four columns: Title, Severity, Vulnerability Type, and CVSS Score.
- The title of the vulnerability should be a clickable link that scrolls the page down to the corresponding detailed
  vulnerability information below the table on the same page.
- The number of rows should match the number of vulnerabilities found in the scan results.
- Bring in EACH and EVERY vulnerability found in the Vulnerability Scan Result.
- Severity should be categorized based on OWASP standards ("Low", "Medium", "High", "Critical").
- Vulnerability Type should specify the type of vulnerability (e.g., "XSS", "SQL Injection" and more).
- Provide a concise title for the vulnerability.
- Provide the CVSS v3.1 score from the pre-calculated scores above.
- Style the table with color-coded rows (dark red for Critical, red for High, yellow for Medium, green for Low).

2. **Detailed Vulnerability Information**
For each vulnerability generate a section with:
- **Title**: Clear descriptive title.
- **Vulnerability Type**: Specific type (e.g., Reflected XSS, SQL Injection).
- **OWASP Severity**: Critical/High/Medium/Low.
- **CVSS v3.1 Score**: Numeric score with severity label.
- **Description**: How the vulnerability occurs, typical attack vectors, OWASP Top 10 link, example consequences.
- **Affected Targets**: Specific endpoints/parameters/URLs.
- **Impact**: Detailed bullet list of risks.
- **Suggested Fix**: Developer-focused numbered remediation steps and secure coding guidance.
- **Proof of Concept (PoC)**: Non-destructive numbered steps showing how the issue was identified, with <pre> code
  blocks for HTTP requests/payloads. Only demonstrate existence of the vulnerability.

**Common Deliverables:**
- Clean, structured HTML with moderate inline CSS.
- Two separate sections: Reconnaissance and Vulnerability Assessment.
- Separate styled boxes for each vulnerability detail heading.
- Color-coded tables.
- No commentary or text outside the HTML tags.

**Format for Recon section:**
1. All potential target subdomains as <li> items.
2. A table below the list with columns: Domain, IP Address, Open Ports, Technologies, Firewall/WAF, SSL/TLS.

**Format for vulnerability assessment result section:**
1. Main page table (four columns) with clickable titles linking to anchored detail sections below.
2. For each vulnerability detail section: Title, Vulnerability Type, Description, Affected Targets, OWASP Severity,
   CVSS v3.1 Score, Impact, Suggested Fix, Proof of Concept – each in its own styled box.
3. Use pre-calculated CVSS scores from {base_scores}.

**Now generate the HTML report strictly following the structure above.**
{html_placeholder}"""


def generate_report(
        recon_info: Dict,
        vulnerability_results: Dict,
        base_scores: Dict,
        security_score: Dict,
        api_key: str = "",
        model: str = "local",
        output_dir: str = "output",
        base_url: str = None,
        exploit_results: Dict = None) -> str:
    """Generate a comprehensive HTML vulnerability report using the LLM."""
    from modules.utils import make_llm_client
    client = make_llm_client(api_key, base_url)

    exploit_section = ""
    if exploit_results:
        exploit_section = f"\n\nExploit execution results (confirmed vulnerabilities with PoC evidence):\n{str(exploit_results)[:3000]}"

    prompt = REPORT_PROMPT.format(
        security_rating=security_score.get('rating', 'Unknown'),
        security_score=security_score.get('score', 0),
        recon_info=str(recon_info)[:3000],
        vuln_results=str(vulnerability_results)[:5000] + exploit_section,
        base_scores=str(base_scores),
        html_placeholder="",
    )

    print("\n[#] Generating vulnerability report with LLM...")
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=6000,
            temperature=0.3,
        )
        report = response.choices[0].message.content.strip()
    except Exception as e:
        print(f"Report generation error: {e}")
        report = f"<html><body><h1>Error generating report: {e}</h1></body></html>"

    path = os.path.join(output_dir, "vulnerability_report.html")
    with open(path, 'w', encoding='utf-8') as f:
        f.write(report)
    print(f"[#] Vulnerability report saved to: {path}")
    return report
