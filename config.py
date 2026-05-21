import os

# LLM Configuration
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
LLM_MODEL = os.environ.get("LLM_MODEL", "gpt-4o")
EMBEDDING_MODEL = "text-embedding-3-small"

# CVSS Configuration
CVSS_LAMBDA = 1.5
CVSS_MAX = 10.0

# Paths
OUTPUT_DIR = "output"
DATA_DIR = "data"
CVSS_DATASET_PATH = os.path.join(DATA_DIR, "cvss_dataset.csv")
FAISS_INDEX_PATH = os.path.join(DATA_DIR, "faiss_index")

# Tool timeouts (seconds)
TIMEOUT_SUBFINDER = 60
TIMEOUT_NMAP = 180
TIMEOUT_GOBUSTER = 180
TIMEOUT_XSS = 180
TIMEOUT_NIKTO = 180
TIMEOUT_TESTSSL = 180
TIMEOUT_WAPITI = 600
TIMEOUT_PARAMSPIDER = 60
TIMEOUT_WAFW00F = 30
TIMEOUT_HTTP = 10

# Gobuster wordlist – probe several standard locations so it works both
# inside the Docker container and on bare-metal Kali / Ubuntu / macOS hosts.
def _find_wordlist() -> str:
    candidates = [
        "/usr/share/wordlists/dirb/common.txt",   # Kali / Docker symlink
        "/usr/share/dirb/wordlists/common.txt",   # Ubuntu/Debian dirb package
        "/opt/homebrew/share/dirb/wordlists/common.txt",  # macOS Homebrew
        "/usr/local/share/wordlists/dirb/common.txt",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    # Last resort – inline a minimal wordlist bundled with the project
    return os.path.join(os.path.dirname(__file__), "data", "wordlist_common.txt")

GOBUSTER_WORDLIST = os.environ.get("GOBUSTER_WORDLIST", _find_wordlist())
