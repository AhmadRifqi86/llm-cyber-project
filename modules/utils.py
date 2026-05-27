import re
import os
import json
from datetime import datetime


def clean_ansi_escape_codes(text: str) -> str:
    """Remove ANSI escape sequences from tool output."""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


def make_llm_client(api_key: str = "", base_url: str = None):
    """Return an OpenAI-compatible client for local or remote LLM."""
    from openai import OpenAI
    kwargs: dict = {"api_key": api_key if api_key else "local"}
    if base_url:
        kwargs["base_url"] = base_url
    return OpenAI(**kwargs)


def make_embeddings(embedding_model: str, provider: str = "local", api_key: str = ""):
    """Return LangChain embeddings: sentence-transformers for local, OpenAIEmbeddings for openai."""
    if provider == "openai":
        from langchain_openai import OpenAIEmbeddings
        return OpenAIEmbeddings(model=embedding_model, openai_api_key=api_key)
    try:
        from langchain_huggingface import HuggingFaceEmbeddings
    except ImportError:
        from langchain_community.embeddings import HuggingFaceEmbeddings
    return HuggingFaceEmbeddings(model_name=embedding_model)


def try_parse_json(text: str):
    """Parse JSON from LLM output, tolerating markdown fences, trailing commas,
    and truncated arrays (salvages complete objects from a partial response)."""
    # Strip code fences
    text = re.sub(r'```(?:json)?\s*', '', text)
    text = re.sub(r'```', '', text).strip()

    # Remove trailing commas globally
    cleaned = re.sub(r',\s*([}\]])', r'\1', text)

    # Direct parse
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # Extract first complete JSON array or object
    for pattern in [r'\[.*?\]', r'\{.*?\}']:
        m = re.search(pattern, cleaned, re.DOTALL)
        if m:
            candidate = re.sub(r',\s*([}\]])', r'\1', m.group())
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                pass

    # Salvage complete objects from a truncated array using brace matching
    objects = []
    depth = 0
    start = None
    for i, ch in enumerate(cleaned):
        if ch == '{':
            if depth == 0:
                start = i
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0 and start is not None:
                candidate = re.sub(r',\s*([}\]])', r'\1', cleaned[start:i + 1])
                try:
                    obj = json.loads(candidate)
                    objects.append(obj)
                except json.JSONDecodeError:
                    pass
                start = None
    if objects:
        return objects

    return None


def create_scan_result_folder(folder_name: str, base_dir: str = "output") -> str:
    """Create a timestamped scan result folder."""
    os.makedirs(os.path.join(base_dir, folder_name), exist_ok=True)
    return os.path.join(base_dir, folder_name)


def save_json(data: dict, filepath: str):
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, default=str)


def save_html(content: str, filepath: str):
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)


def print_section(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def print_step(msg: str):
    print(f"\n[#] {msg}")


def print_info(msg: str):
    print(f"[-] {msg}")
