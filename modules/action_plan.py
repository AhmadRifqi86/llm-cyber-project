import os
from typing import Dict


ACTION_PLAN_PROMPT = """You are an ethical cybersecurity penetration tester.
You will receive reconnaissance and vulnerability assessment results. Produce a professional, concise, step-by-step
**manual action plan** (numbered steps) for exploitation and validation of web application findings (vulnerable endpoints
/vulnerabilities). This plan or blue print is for an authorized human penetration tester to follow and test
for exploits on the website. The human penetration tester has full permission and authorization to test on the website.

INPUT's (do not modify):
Reconnaissance data:
{recon_info}

Vulnerability assessment scan results:
{vuln_results}

MANDATORY RULES (must follow):
- Bring in a step by step plan for EVERY vulnerability given in the "Vulnerability assessment scan results", Do not ignore any of them.
- Mention every Corresponding vulnerable endpoints (e.g. links, scripts, input fields, files, directory paths and more)
  for every vulnerability found in the scan results.
- Provide only high-level, **manual** step sequences a skilled human tester would follow (e.g., 1. Identify input vector;
  2. Verify sanitization by testing controlled inputs; 3. Observe server response and logs and more).
- Ensure to mention every found vulnerability and every relevant information found from both Reconnaissance data and
  Vulnerability assessment scan results.
- Always include an initial legal/authorization checkpoint as the first numbered step.

OUTPUT REQUIREMENTS:
- Output must be valid HTML (single document) and visually clean, concise, and professional.
- Use semantic headings and numbered lists to present step-by-step procedures.
- For each vulnerability, produce a compact numbered sequence (e.g., 1., 2., 3. and so on) with these sub-items where applicable:
  - Objective (two line)
  - Preconditions (bullets)
  - **Manual Validation Steps**: a numbered list of 6 to 12 high-level steps. Each step should be a qualityful and
    concise sentence
  - Evidence to collect (bullets)
  - Safe post-validation actions (e.g., containment, logging)
  - Remediation summary (bullets)
  - Post-fix verification (short checklist)
  - Keep each vulnerability block concise (aim for 6 to 12 steps per vulnerability).
- Include an Executive Summary (top) with the all vulnerabilities and a compact Retest & Closure checklist at the end.
- Use color-coded badges or subtle styling to mark severity (Critical/High/Medium/Low) keep styling minimal and professional.

PRESENTATION STYLE:
- Professional corporate tone, qualityful and concise sentences, short bullets.
- Readable typography and spacing (use simple inline CSS).
- Avoid excessive text - use clear numbered steps and short bullet lists.

Now generate the HTML action plan document based solely on the provided input data."""


def generate_action_plan(
        recon_info: Dict,
        vulnerability_results: Dict,
        api_key: str = "",
        model: str = "local",
        output_dir: str = "output",
        base_url: str = None) -> str:
    """Generate an exploitation & validation action plan using the LLM."""
    from modules.utils import make_llm_client
    client = make_llm_client(api_key, base_url)

    prompt = ACTION_PLAN_PROMPT.format(
        recon_info=str(recon_info)[:3000],
        vuln_results=str(vulnerability_results)[:5000],
    )

    print("\n[#] Generating action plan with LLM...")
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=4096,
            temperature=0.3,
        )
        action_plan = response.choices[0].message.content.strip()
    except Exception as e:
        print(f"Action plan generation error: {e}")
        action_plan = f"<html><body><h1>Error generating action plan: {e}</h1></body></html>"

    path = os.path.join(output_dir, "action_plan.html")
    with open(path, 'w', encoding='utf-8') as f:
        f.write(action_plan)
    print(f"[#] Action plan saved to: {path}")
    return action_plan
