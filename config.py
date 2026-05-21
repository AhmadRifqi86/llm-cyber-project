import os

# ---------------------------------------------------------------------------
# LLM Configuration
# ---------------------------------------------------------------------------
# Provider: "local"  – any OpenAI-compatible local server (llama.cpp, Ollama, LM Studio, vLLM …)
#           "openai" – OpenAI API (requires OPENAI_API_KEY)
LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "local")

# Base URL for the local LLM server.
# llama.cpp default:  http://localhost:8080/v1
# Ollama default:     http://localhost:11434/v1
# LM Studio default:  http://localhost:1234/v1
LLM_BASE_URL = os.environ.get("LLM_BASE_URL", "http://localhost:8080/v1")

# Model name sent in API requests.
# llama.cpp ignores this field (uses whatever model is loaded).
# For Ollama set to the pulled model name, e.g. "llama3.2" or "mistral".
LLM_MODEL = os.environ.get("LLM_MODEL", "local")

# Sentence-transformers model used for RAG embeddings (downloaded locally, no API key needed).
# Override to an OpenAI model name when LLM_PROVIDER=openai.
EMBEDDING_MODEL = os.environ.get("EMBEDDING_MODEL", "all-MiniLM-L6-v2")

# OpenAI API key – only required when LLM_PROVIDER=openai
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")

# ---------------------------------------------------------------------------
# CVSS Configuration
# ---------------------------------------------------------------------------
CVSS_LAMBDA = 1.5
CVSS_MAX = 10.0

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
OUTPUT_DIR = "output"
DATA_DIR = "data"
CVSS_DATASET_PATH = os.path.join(DATA_DIR, "cvss_dataset.csv")
FAISS_INDEX_PATH = os.path.join(DATA_DIR, "faiss_index")

# ---------------------------------------------------------------------------
# Tool timeouts (seconds)
# ---------------------------------------------------------------------------
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
TIMEOUT_SQLMAP = 300
TIMEOUT_EXPLOIT = 30

# ---------------------------------------------------------------------------
# Gobuster wordlist – probe several standard locations so it works both
# inside the Docker container and on bare-metal Kali / Ubuntu / macOS hosts.
# ---------------------------------------------------------------------------
def _find_wordlist() -> str:
    candidates = [
        "/usr/share/wordlists/dirb/common.txt",           # Kali / Docker symlink
        "/usr/share/dirb/wordlists/common.txt",           # Ubuntu/Debian dirb package
        "/opt/homebrew/share/dirb/wordlists/common.txt",  # macOS Homebrew
        "/usr/local/share/wordlists/dirb/common.txt",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return os.path.join(os.path.dirname(__file__), "data", "wordlist_common.txt")

GOBUSTER_WORDLIST = os.environ.get("GOBUSTER_WORDLIST", _find_wordlist())
