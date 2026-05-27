import re
import ssl
import socket
import subprocess
import urllib3
import requests
from typing import Dict, List, Tuple

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from modules.utils import clean_ansi_escape_codes, print_step, print_info
from config import (
    TIMEOUT_SUBFINDER, TIMEOUT_NMAP, TIMEOUT_WAFW00F,
    TIMEOUT_PARAMSPIDER, TIMEOUT_HTTP
)


def _hostname(domain: str) -> str:
    """Return just the hostname/IP, stripping any :port suffix."""
    return domain.split(':')[0]


def certificate_data_lookup(domain: str) -> List[str]:
    """Search subdomains via crt.sh certificate transparency logs."""
    subdomains = []
    try:
        url = f"https://crt.sh/?q=%.{_hostname(domain)}&output=json"
        response = requests.get(url, timeout=TIMEOUT_HTTP)
        if response.status_code == 200:
            data = response.json()
            pattern = re.compile(
                r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
            )
            for entry in data:
                for name in entry.get('name_value', '').split('\n'):
                    name = name.strip().lstrip('*.')
                    if pattern.match(name) and name not in subdomains:
                        subdomains.append(name)
    except Exception as e:
        print(f"Error in https query for domain data lookup: {e}")
    return subdomains


def tool_enum(domain: str) -> List[str]:
    """Enumerate subdomains using Subfinder."""
    subdomains = []
    try:
        result = subprocess.run(
            ['subfinder', '-d', _hostname(domain), '-silent'],
            capture_output=True, text=True, timeout=TIMEOUT_SUBFINDER
        )
        for line in result.stdout.splitlines():
            sub = line.strip()
            if sub:
                subdomains.append(sub)
    except FileNotFoundError:
        print("subfinder not found, skipping tool-based subdomain enumeration.")
    except subprocess.TimeoutExpired:
        print("subfinder timed out.")
    except Exception as e:
        print(f"subfinder error: {e}")
    return subdomains


def get_unique_subdomains(cert_subs: List[str], tool_subs: List[str], domain: str) -> List[str]:
    """Combine, deduplicate and clean subdomain lists."""
    combined = list(set(cert_subs + tool_subs))
    cleaned = []
    for sub in combined:
        sub = sub.lstrip('*.')
        if sub and sub not in cleaned:
            cleaned.append(sub)
    if domain not in cleaned:
        cleaned.insert(0, domain)
    return cleaned


def domain_active_check(subdomains: List[str]) -> List[str]:
    """Return only subdomains that respond with HTTP status < 400."""
    active = []
    for sub in subdomains:
        for scheme in ['https', 'http']:
            try:
                resp = requests.get(
                    f"{scheme}://{sub}", timeout=5,
                    allow_redirects=True, verify=False
                )
                if resp.status_code < 400:
                    if sub not in active:
                        active.append(sub)
                    break
            except Exception:
                continue
    return active


def _is_ip(s: str) -> bool:
    import re as _re
    return bool(_re.match(r'^\d{1,3}(\.\d{1,3}){3}$', s))


def get_ip(subdomains: List[str]) -> Dict[str, List[str]]:
    """Resolve IP addresses for each subdomain using nslookup / socket."""
    ip_map = {}
    for sub in subdomains:
        host = _hostname(sub)
        # If the target is already an IP, use it directly — nslookup on an IP
        # does reverse DNS and returns the DNS server address, not the target.
        if _is_ip(host):
            ip_map[sub] = [host]
            continue
        try:
            result = subprocess.run(
                ['nslookup', host], capture_output=True, text=True, timeout=10
            )
            ips = re.findall(r'Address:\s+(\d+\.\d+\.\d+\.\d+)', result.stdout)
            # Filter out the DNS server's own address (first Address: line)
            ips = ips[1:] if len(ips) > 1 else ips
            ip_map[sub] = list(set(ips)) if ips else []
        except Exception:
            try:
                ip = socket.gethostbyname(host)
                ip_map[sub] = [ip]
            except Exception:
                ip_map[sub] = []
    return ip_map


def find_open_ports(unique_ips: List[str]) -> Dict[str, List[int]]:
    """Scan open ports on each IP using nmap."""
    port_map = {}
    for ip in unique_ips:
        try:
            result = subprocess.run(
                ['nmap', '-T4', '--open', '-p', '1-10000', ip, '-oG', '-'],
                capture_output=True, text=True, timeout=TIMEOUT_NMAP
            )
            ports = re.findall(r'(\d+)/open', result.stdout)
            port_map[ip] = [int(p) for p in ports]
        except FileNotFoundError:
            print("nmap not found, skipping port scan.")
            port_map[ip] = []
        except subprocess.TimeoutExpired:
            print(f"nmap timed out for {ip}")
            port_map[ip] = []
        except Exception as e:
            print(f"nmap error for {ip}: {e}")
            port_map[ip] = []
    return port_map


def _probe_scheme(domain: str) -> str:
    """Return 'https' if domain responds on port 443, else 'http'."""
    host = _hostname(domain)
    try:
        import ssl as _ssl, socket as _socket
        ctx = _ssl.create_default_context()
        with _socket.create_connection((host, 443), timeout=5) as s:
            with ctx.wrap_socket(s, server_hostname=host):
                return 'https'
    except Exception:
        return 'http'


def techstack(domain: str) -> Dict:
    """Identify web technology stack via python-Wappalyzer or header inspection."""
    scheme = _probe_scheme(domain)
    tech = {}
    try:
        from Wappalyzer import Wappalyzer, WebPage
        import warnings
        warnings.filterwarnings('ignore')
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url(f"{scheme}://{domain}", timeout=TIMEOUT_HTTP)
        tech = wappalyzer.analyze_with_categories(webpage)
    except ImportError:
        try:
            resp = requests.get(f"{scheme}://{domain}", timeout=TIMEOUT_HTTP, verify=False)
            h = resp.headers
            for key in ['Server', 'X-Powered-By', 'X-Generator', 'Via']:
                if h.get(key):
                    tech[key] = {'versions': [], 'categories': ['Headers']}
        except Exception as e:
            print(f"Tech stack detection error: {e}")
    except Exception as e:
        print(f"Wappalyzer error: {e}")
    return tech


def firewall_check(domain: str) -> str:
    """Detect web application firewall using wafw00f."""
    scheme = _probe_scheme(domain)
    try:
        result = subprocess.run(
            ['wafw00f', f'{scheme}://{domain}'],
            capture_output=True, text=True, timeout=TIMEOUT_WAFW00F
        )
        return clean_ansi_escape_codes(result.stdout)
    except FileNotFoundError:
        return "wafw00f not found, WAF detection skipped."
    except Exception as e:
        return f"WAF check error: {e}"


def check_ssl_support(domain: str) -> Tuple[bool, str]:
    """Check whether the domain supports TLS/SSL on port 443."""
    host = _hostname(domain)
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                version = ssock.version()
                return True, f"SSL/TLS supported ({version})"
    except ssl.SSLError as e:
        return False, f"SSL error: {e}"
    except (ConnectionRefusedError, OSError):
        return False, f"[X] {domain} does NOT support SSL/TLS (connection refused)"
    except socket.timeout:
        return False, f"[X] {domain} does NOT support SSL/TLS (TimeoutError)"
    except Exception as e:
        return False, f"[X] {domain} does NOT support SSL/TLS: {e}"


def get_parameters(domain: str, output_dir: str) -> str:
    """Fetch URL parameters using ParamSpider."""
    out_file = f"{output_dir}/params_{domain}.txt"
    try:
        subprocess.run(
            ['paramspider', '--domain', _hostname(domain), '--output', out_file],
            capture_output=True, text=True, timeout=TIMEOUT_PARAMSPIDER
        )
        return f"Parameters saved to {out_file}"
    except FileNotFoundError:
        return "paramspider not found, parameter fetching skipped."
    except Exception as e:
        return f"paramspider error: {e}"


def run_reconnaissance(domain: str, output_dir: str) -> Dict:
    """Execute the full reconnaissance pipeline and return collected data."""
    print_step(f"Reconnaissance Module")
    print_step(f"Starting reconnaissance for the domain = {domain}")

    recon_info: Dict = {
        'domain': domain,
        'subdomains': [],
        'active_subdomains': [],
        'ip_addresses': {},
        'unique_ips': [],
        'open_ports': {},
        'tech_stack': {},
        'firewall': '',
        'ssl_tls': (False, ''),
        'parameters': '',
    }

    # 1. crt.sh
    print_step("Starting certificate data lookup:")
    cert_subs = certificate_data_lookup(domain)
    print(f"Number of subdomains found from public Lookup is : {len(cert_subs)}")

    # 2. Subfinder
    print_step("Starting subdomain enumeration using tool:")
    tool_subs = tool_enum(domain)
    print(f"Number of subdomains found using tool is : {len(tool_subs)}")

    # 3. Unique subdomains
    unique = get_unique_subdomains(cert_subs, tool_subs, domain)
    print(f"\nTotal no. of unique subdomains found:{len(unique)}")
    print(f"subdomain list:{unique}")
    recon_info['subdomains'] = unique

    # 4. Active check
    active = domain_active_check(unique)
    if not active:
        active = [domain]
    print_step(f"Total no. of active subdomains found is : {len(active)}")
    for s in active:
        print(f"-{s}")
    recon_info['active_subdomains'] = active

    # 5. IP resolution
    print_step("Fetching IP addresses:")
    ip_map = get_ip(active)
    for sub, ips in ip_map.items():
        print(f"{sub} = {ips}")
    all_ips = list(set(ip for ips in ip_map.values() for ip in ips))
    print(f"[#]Active and unique IP addresses are:")
    for ip in all_ips:
        print(f"- {ip}")
    recon_info['ip_addresses'] = ip_map
    recon_info['unique_ips'] = all_ips

    # 6. Port scanning
    print_step("Searching for open ports:")
    ports = find_open_ports(all_ips)
    print(f"[#] Open ports associated with each unique IP address:")
    print(ports)
    recon_info['open_ports'] = ports

    # 7. Technology stack
    print_step(f"Technology stack of the main domain:{domain} are:")
    tech = techstack(domain)
    for t, info in tech.items():
        print(f"{t} : {info}")
    recon_info['tech_stack'] = tech

    # 8. Firewall
    print_step("Firewall detection result:")
    fw = firewall_check(domain)
    print(fw)
    recon_info['firewall'] = fw

    # 9. SSL/TLS
    print_step("SSL/TLS Certification result:")
    ssl_result = check_ssl_support(domain)
    print(f"{ssl_result}")
    recon_info['ssl_tls'] = ssl_result

    # 10. Parameters
    print_step(f"Parameter Fetching for {domain} completed")
    param_result = get_parameters(domain, output_dir)
    print(param_result)
    recon_info['parameters'] = param_result

    return recon_info


def discover_web_ports(recon_info: Dict, primary_domain: str) -> List[str]:
    """
    Probe each discovered open port with HTTP and return additional
    host:port targets that respond, excluding the primary domain's port.
    """
    primary_host = _hostname(primary_domain)
    primary_port_str = primary_domain.split(':')[1] if ':' in primary_domain else ''
    primary_port = int(primary_port_str) if primary_port_str.isdigit() else None

    extra: List[str] = []
    for ip, ports in recon_info.get('open_ports', {}).items():
        host = primary_host if _is_ip(primary_host) else ip
        for port in ports:
            if primary_port and port == primary_port:
                continue
            target = f"{host}:{port}"
            for scheme in ['http', 'https']:
                try:
                    resp = requests.get(
                        f"{scheme}://{target}", timeout=5,
                        verify=False, allow_redirects=True
                    )
                    if resp.status_code < 500:
                        print_info(f"Additional web target found: {scheme}://{target} (HTTP {resp.status_code})")
                        extra.append(target)
                        break
                except Exception:
                    continue
    return extra


def crawl_forms(active_subdomains: List[str]) -> List[Dict]:
    """
    Crawl active subdomains (shallow, max 20 pages per host) to discover
    HTML forms, their action URLs, HTTP methods, and input field names.
    Returns a list of form dicts for use by the exploit planner.
    """
    from html.parser import HTMLParser
    from urllib.parse import urljoin, urlparse as _urlparse

    class _FormParser(HTMLParser):
        def __init__(self):
            super().__init__()
            self.forms: List[Dict] = []
            self._cur: Dict = {}

        def handle_starttag(self, tag, attrs):
            a = dict(attrs)
            if tag == 'form':
                self._cur = {
                    'action': a.get('action', ''),
                    'method': a.get('method', 'get').upper(),
                    'inputs': [],
                }
            elif tag in ('input', 'textarea', 'select') and self._cur:
                name = a.get('name', '')
                if name:
                    self._cur['inputs'].append({
                        'name': name,
                        'type': a.get('type', 'text'),
                        'value': a.get('value', 'test'),
                    })

        def handle_endtag(self, tag):
            if tag == 'form' and self._cur:
                self.forms.append(self._cur)
                self._cur = {}

    class _LinkParser(HTMLParser):
        def __init__(self):
            super().__init__()
            self.links: List[str] = []

        def handle_starttag(self, tag, attrs):
            if tag == 'a':
                href = dict(attrs).get('href', '')
                if href and not href.startswith(('#', 'mailto:', 'javascript:')):
                    self.links.append(href)

    all_forms: List[Dict] = []
    visited: set = set()

    for sub in active_subdomains:
        for scheme in ['http', 'https']:
            base = f"{scheme}://{sub}"
            queue = [base]
            crawled = 0

            while queue and crawled < 20:
                url = queue.pop(0)
                if url in visited:
                    continue
                visited.add(url)
                crawled += 1

                try:
                    resp = requests.get(url, timeout=8, verify=False,
                                        allow_redirects=True)
                    if resp.status_code >= 400:
                        continue
                    if 'html' not in resp.headers.get('Content-Type', ''):
                        continue

                    fp = _FormParser()
                    fp.feed(resp.text)
                    for form in fp.forms:
                        action = form['action'] or url
                        if not action.startswith('http'):
                            action = urljoin(url, action)
                        all_forms.append({
                            'page_url': url,
                            'form_action': action,
                            'method': form['method'],
                            'inputs': form['inputs'],
                        })

                    lp = _LinkParser()
                    lp.feed(resp.text)
                    base_netloc = _urlparse(base).netloc
                    for href in lp.links:
                        abs_url = urljoin(url, href)
                        if _urlparse(abs_url).netloc == base_netloc:
                            queue.append(abs_url)

                    break  # got a valid response, skip other schemes
                except Exception:
                    continue

    if all_forms:
        print_info(f"Form crawler: found {len(all_forms)} form(s) across {len(visited)} page(s).")
    else:
        print_info("Form crawler: no forms discovered.")
    return all_forms
