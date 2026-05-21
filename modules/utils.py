import re
import os
import json
from datetime import datetime


def clean_ansi_escape_codes(text: str) -> str:
    """Remove ANSI escape sequences from tool output."""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


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
