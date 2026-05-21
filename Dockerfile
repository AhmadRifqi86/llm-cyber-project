# =============================================================================
# Automated Web-App Penetration Testing Framework
# Based on: "Automating Web Application Vulnerability Detection:
#   A Generative AI and Security Tool Based Penetration Testing Framework"
#   Brac University, October 2025
#
# Build:   docker build -t cyberpentest .
#
# Run with local llama.cpp (default):
#   docker compose run --rm pentest example.com
#
# Run with OpenAI:
#   LLM_PROVIDER=openai OPENAI_API_KEY=sk-... docker compose run --rm pentest example.com
# =============================================================================

FROM python:3.11-slim-bookworm

# ---------------------------------------------------------------------------
# Build-time arguments (pin versions for reproducibility)
# ---------------------------------------------------------------------------
ARG SUBFINDER_VERSION=2.6.6
ARG GOBUSTER_VERSION=3.6.0

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # Make CLI tools installed via pip visible system-wide
    PATH="/usr/local/bin:/root/.local/bin:${PATH}"

# ---------------------------------------------------------------------------
# Layer 1 – System packages
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        # Core utilities
        curl wget git unzip ca-certificates \
        # DNS lookup (nslookup)
        dnsutils \
        # Network scanner
        nmap \
        # Web server scanner (Perl-based)
        nikto \
        # SSL/TLS test dependencies (used by testssl.sh)
        openssl \
        # Perl SSL library needed by testssl.sh
        perl libio-socket-ssl-perl libnet-ssleay-perl \
        # Directory brute-force wordlists
        dirb \
        # SQL injection exploitation
        sqlmap \
        # Miscellaneous
        procps \
    && rm -rf /var/lib/apt/lists/*

# Create the Kali-compatible wordlist symlink path used by config.py
RUN mkdir -p /usr/share/wordlists && \
    ln -sfn /usr/share/dirb/wordlists /usr/share/wordlists/dirb

# ---------------------------------------------------------------------------
# Layer 2 – Go-based binaries (pre-built, architecture-aware)
# ---------------------------------------------------------------------------

# --- Subfinder (passive subdomain discovery) ---
RUN set -e && \
    ARCH=$(dpkg --print-architecture) && \
    case "$ARCH" in \
        amd64)  SF_ARCH="amd64" ;; \
        arm64)  SF_ARCH="arm64" ;; \
        *)      echo "Unsupported arch: $ARCH" && exit 1 ;; \
    esac && \
    wget -qO /tmp/subfinder.zip \
        "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${SF_ARCH}.zip" && \
    unzip -qo /tmp/subfinder.zip subfinder -d /usr/local/bin && \
    chmod +x /usr/local/bin/subfinder && \
    rm /tmp/subfinder.zip && \
    subfinder -version 2>&1 | head -1

# --- Gobuster (directory/file brute-force) ---
RUN set -e && \
    ARCH=$(dpkg --print-architecture) && \
    case "$ARCH" in \
        amd64)  GB_ARCH="x86_64" ;; \
        arm64)  GB_ARCH="arm64" ;; \
        *)      echo "Unsupported arch: $ARCH" && exit 1 ;; \
    esac && \
    wget -qO /tmp/gobuster.tar.gz \
        "https://github.com/OJ/gobuster/releases/download/v${GOBUSTER_VERSION}/gobuster_Linux_${GB_ARCH}.tar.gz" && \
    tar -xzf /tmp/gobuster.tar.gz -C /usr/local/bin gobuster && \
    chmod +x /usr/local/bin/gobuster && \
    rm /tmp/gobuster.tar.gz && \
    gobuster version 2>&1 | head -1

# ---------------------------------------------------------------------------
# Layer 3 – testssl.sh (SSL/TLS scanner)
# ---------------------------------------------------------------------------
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh && \
    chmod +x /opt/testssl.sh/testssl.sh && \
    ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl && \
    ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

# ---------------------------------------------------------------------------
# Layer 4 – Python security tools (pip)
# ---------------------------------------------------------------------------

# wafw00f – Web Application Firewall detector
RUN pip install --no-cache-dir wafw00f && wafw00f --version 2>&1 | head -1

# wapiti3 – Black-box web vulnerability scanner
RUN pip install --no-cache-dir wapiti3 && wapiti --version 2>&1 | head -1

# PwnXSS – XSS scanner
# Try PyPI first; fall back to GitHub clone if not available
RUN pip install --no-cache-dir pwnxss 2>/dev/null || ( \
        git clone --depth 1 https://github.com/pwn0sec/PwnXSS.git /opt/PwnXSS && \
        pip install --no-cache-dir -r /opt/PwnXSS/requirements.txt && \
        chmod +x /opt/PwnXSS/pwnxss.py && \
        ln -s /opt/PwnXSS/pwnxss.py /usr/local/bin/pwnxss \
    )

# ParamSpider – URL parameter discovery
# Install from GitHub because PyPI version may be stale
RUN git clone --depth 1 https://github.com/devanshbatham/ParamSpider.git /opt/ParamSpider && \
    pip install --no-cache-dir -r /opt/ParamSpider/requirements.txt && \
    pip install --no-cache-dir /opt/ParamSpider 2>/dev/null || ( \
        chmod +x /opt/ParamSpider/paramspider/main.py && \
        echo '#!/bin/sh\npython3 /opt/ParamSpider/paramspider/main.py "$@"' > /usr/local/bin/paramspider && \
        chmod +x /usr/local/bin/paramspider \
    )

# python-Wappalyzer – technology stack detection
RUN pip install --no-cache-dir python-Wappalyzer 2>/dev/null || true

# ---------------------------------------------------------------------------
# Layer 5 – Framework Python dependencies
# ---------------------------------------------------------------------------
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-download the sentence-transformers embedding model so RAG works offline
RUN python3 -c "from sentence_transformers import SentenceTransformer; \
                SentenceTransformer('all-MiniLM-L6-v2'); \
                print('Embedding model cached OK')"

# ---------------------------------------------------------------------------
# Layer 6 – Project source
# ---------------------------------------------------------------------------
COPY . .

# Ensure output/data directories exist with correct permissions
RUN mkdir -p output data/faiss_index && chmod -R 777 output data

# ---------------------------------------------------------------------------
# Volumes (mount from host for persistent scan results & FAISS cache)
# ---------------------------------------------------------------------------
VOLUME ["/app/output", "/app/data"]

# ---------------------------------------------------------------------------
# Smoke-test: verify all critical tools are reachable at image build time
# ---------------------------------------------------------------------------
RUN echo "=== Tool availability check ===" && \
    nmap --version          | head -1 && \
    nikto -Version 2>&1     | head -1 && \
    subfinder -version 2>&1 | head -1 && \
    gobuster version 2>&1   | head -1 && \
    wafw00f --version 2>&1  | head -1 && \
    wapiti --version 2>&1   | head -1 && \
    testssl --version 2>&1  | head -2 && \
    sqlmap --version 2>&1   | head -1 && \
    python3 -c "from modules.cvss_scoring import calculate_cvss_base_score; \
                s=calculate_cvss_base_score({'AV':'N','AC':'L','PR':'N','UI':'N','S':'U','C':'H','I':'H','A':'H'}); \
                assert s == 9.8, f'CVSS check failed: {s}'; print(f'CVSS self-test: 9.8 OK')" && \
    python3 -c "from modules.exploit import run_exploit_phase; print('Exploit module: OK')" && \
    echo "=== All checks passed ==="

# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
ENTRYPOINT ["python3", "main.py"]
CMD ["--help"]
