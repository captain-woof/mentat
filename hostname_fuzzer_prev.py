#!/usr/bin/env python3
"""
host_header_sni_multi_with_certs.py

High-performance Host-header + SNI fuzzing using pycurl.Multi,
with certificate hostname discovery and dynamic baseline augmentation.

Requirements: pycurl, beautifulsoup4, idna
"""

import pycurl
from io import BytesIO
import ssl
import socket
from bs4 import BeautifulSoup
import re
import csv
import time
import random
import string
import hashlib
import urllib.parse
import html
from typing import Dict, List, Set, Tuple
from browserforge.headers import Browser, HeaderGenerator



# ------------------ CONFIG ------------------
BROWSER = Browser(name="chrome")
BROWSER_HEADER = HeaderGenerator(browser=BROWSER, os="windows").generate()
BASELINE_TESTS = 2
USER_AGENT = BROWSER_HEADER["User-Agent"]
# ------------------------------------------------

# ---------------- Utilities ----------------
def rand_host() -> str:
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=10)) + ".invalidlocaltest"

def norm_whitespace(s: str) -> str:
    return re.sub(r'\s+', ' ', s).strip()

def hash_text(s: str) -> str:
    return hashlib.sha256(s.encode('utf-8', errors='ignore')).hexdigest()

def extract_title(html_text: str) -> str:
    if not html_text:
        return ""
    try:
        soup = BeautifulSoup(html_text, "html.parser")
        t = soup.title.string if soup.title and soup.title.string else ""
        return t.strip()
    except Exception:
        m = re.search(r'<title[^>]*>(.*?)</title>', html_text, re.IGNORECASE | re.DOTALL)
        return (m.group(1).strip() if m else "")

def escape_variants(s: str) -> List[str]:
    variants = set()
    s = s or ""
    variants.add(s)
    try:
        variants.add(urllib.parse.quote(s, safe=''))
    except Exception:
        variants.add(s)
    variants.add(html.escape(s))
    if s.startswith("www."):
        variants.add(s[4:])
    else:
        variants.add("www." + s)
    return [re.escape(v) for v in variants if v]

def urllib_parse_quote(s: str) -> str:
    try:
        return urllib.parse.quote(s, safe='')
    except Exception:
        return s

# ------------- bytes/text helpers -------------
def bytes_to_text(b: bytes) -> str:
    if not b:
        return ""
    for enc in ('utf-8', 'iso-8859-1'):
        try:
            return b.decode(enc)
        except Exception:
            continue
    return b.decode('utf-8', errors='replace')

# ------------- low-level single curl perform (used in baseline & small probes) -------------
def curl_perform_once(url: str, host_header: str, resolve: List[str], timeout: int) -> Tuple[bool,int,Dict[str,str],bytes,str]:
    buffer = BytesIO()
    header_buf = BytesIO()
    c = pycurl.Curl()
    try:
        c.setopt(pycurl.URL, url.encode('utf-8'))
        c.setopt(pycurl.WRITEDATA, buffer)
        c.setopt(pycurl.HEADERFUNCTION, header_buf.write)
        c.setopt(pycurl.HTTPHEADER, [f"Host: {host_header}", f"User-Agent: {USER_AGENT}"])
        c.setopt(pycurl.CONNECTTIMEOUT, timeout)
        c.setopt(pycurl.TIMEOUT, timeout)
        c.setopt(pycurl.FOLLOWLOCATION, 0)
        c.setopt(pycurl.SSL_VERIFYPEER, 0)
        c.setopt(pycurl.SSL_VERIFYHOST, 0)
        if resolve:
            c.setopt(pycurl.RESOLVE, resolve)
        c.perform()
        status = int(c.getinfo(pycurl.RESPONSE_CODE) or 0)
        header_bytes = header_buf.getvalue()
        try:
            header_text = header_bytes.decode('iso-8859-1')
        except:
            header_text = header_bytes.decode('utf-8', errors='replace')
        headers = {}
        for line in header_text.splitlines():
            if ':' in line:
                k, v = line.split(':',1)
                headers[k.strip().lower()] = v.strip()
        return True, status, headers, buffer.getvalue(), ""
    except pycurl.error as e:
        errno, msg = e.args
        return False, 0, {}, b"", f"{errno}:{msg}"
    finally:
        c.close()

# ------------- TLS cert hostname fetcher -------------
def fetch_cert_hostnames(ip: str, port: int, server_hostname: str, timeout: int = 5) -> List[str]:
    """
    Connect to ip:port with SNI set to server_hostname and extract cert SANs + CN.
    Ignores verification errors, returns list of hostnames (may include wildcards).
    """
    hostnames = []
    try:
        ctx = ssl.create_default_context()
        # don't verify to match "ignore ssl errors"
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                cert = ssock.getpeercert()
                # SANs
                san = cert.get('subjectAltName', ())
                for typ, val in san:
                    if typ.lower() in ('dns',):
                        hostnames.append(val)
                # CN fallback
                subj = cert.get('subject', ())
                for part in subj:
                    for k, v in part:
                        if k == 'commonName':
                            hostnames.append(v)
    except Exception:
        # If any TLS/connection error occurs, return empty list (we don't raise)
        return []
    # dedupe and return
    out = []
    for h in hostnames:
        if h not in out:
            out.append(h)
    return out

# ------------- heuristics for noise tokens -------------
def looks_like_noise_token(tok: str) -> bool:
    if re.fullmatch(r'\d{4}-\d{2}-\d{2}', tok): return True
    if re.fullmatch(r'\d{2}:\d{2}:\d{2}', tok): return True
    if re.fullmatch(r'[0-9a-fA-F]{8,}', tok): return True
    if re.fullmatch(r'[A-Za-z0-9_\-]{20,}', tok): return True
    if re.fullmatch(r'\d+', tok): return True
    if re.fullmatch(r'[A-Za-z0-9+/=]{16,}', tok): return True
    return False

# ------------- baseline building (per ip:port) -------------
def build_baseline(ipport: str, baseline_tests: int, timeout: int) -> Dict:
    ip, port = ipport.split(":")[0], int(ipport.split(":")[1])
    random_hosts = [rand_host() for _ in range(baseline_tests)]
    texts = []
    for rh in random_hosts:
        resolve = [f"{rh}:{port}:{ip}"]
        ok, status, headers, body_bytes, err = curl_perform_once(f"http://{rh}:{port}/", rh, resolve, timeout)
        if not ok or (status and status >= 400 and status < 600 and not body_bytes):
            ok, status, headers, body_bytes, err = curl_perform_once(f"https://{rh}:{port}/", rh, resolve, timeout)
        body_text = bytes_to_text(body_bytes)
        texts.append((rh, body_text or ""))

    # explicit reflections
    reflected = set()
    for rh, body in texts:
        if body and rh in body:
            for pat in escape_variants(rh):
                reflected.add(pat)

    # token variance detection
    token_sets = []
    token_re = re.compile(r'\b[\w@./:-]{4,}\b')
    for _, body in texts:
        tokens = set(token_re.findall(body))
        token_sets.append(tokens)
    variable_tokens = set()
    if token_sets:
        common = set.intersection(*token_sets) if len(token_sets) > 1 else token_sets[0]
        union = set.union(*token_sets)
        variable = union - common
        for t in variable:
            if looks_like_noise_token(t):
                variable_tokens.add(re.escape(t))

    # include IP forms
    variable_tokens.add(re.escape(ip))
    variable_tokens.add(re.escape(f"{ip}:{port}"))
    variable_tokens.add(re.escape(urllib.parse.quote(ip)))
    variable_tokens.add(re.escape(html.escape(ip)))

    # raw baseline request (Host = ip)
    resolve_ip = [f"{ip}:{port}:{ip}"]
    ok, status, headers, body_bytes, err = curl_perform_once(f"http://{ip}:{port}/", ip, resolve_ip, timeout)
    if not ok or (status and status >= 400 and status < 600 and not body_bytes):
        ok, status, headers, body_bytes, err = curl_perform_once(f"https://{ip}:{port}/", ip, resolve_ip, timeout)
    raw_text = bytes_to_text(body_bytes)
    reflected_patterns = set(reflected) | variable_tokens

    cleaned_raw = clean_body(raw_text, reflected_patterns)
    baseline_hash = hash_text(norm_whitespace(cleaned_raw))

    return {
        "ipport": ipport,
        "reflected_patterns": reflected_patterns,
        "baseline_hash": baseline_hash,
        "raw_text": raw_text or "",
    }

# ------------- body cleaning -------------
def clean_body(body: str, reflected_patterns: Set[str]) -> str:
    if not body:
        return ""
    body = re.sub(r'(?is)<script.*?>.*?</script>', ' ', body)
    body = re.sub(r'(?is)<style.*?>.*?</style>', ' ', body)
    body = re.sub(r'(?s)<!--.*?-->', ' ', body)
    body = re.sub(r'(?is)<meta\b[^>]*\bcontent=["\'].*?["\'][^>]*>', ' ', body)
    body = re.sub(r'(?is)<header\b.*?>.*?</header>', ' ', body)
    body = re.sub(r'(?is)<footer\b.*?>.*?</footer>', ' ', body)
    for pat in reflected_patterns:
        try:
            body = re.sub(pat, ' ', body, flags=re.IGNORECASE)
        except re.error:
            body = body.replace(pat, ' ')
    body = re.sub(r'\b[0-9a-fA-F]{8,}\b', ' ', body)
    body = re.sub(r'\b[A-Za-z0-9+/=]{16,}\b', ' ', body)
    body = re.sub(r'\b\d{10,}\b', ' ', body)
    return norm_whitespace(body)

# ------------- Job object & easy construction -------------
class Job:
    def __init__(self, ipport: str, domain: str, attempt: int = 0, scheme: str = "http"):
        self.ipport = ipport
        self.domain = domain
        self.attempt = attempt
        self.scheme = scheme  # "http" or "https"
        self.status = None
        self.headers = {}
        self.body = b""
        self.error = ""
        ip, port = ipport.split(":")[0], ipport.split(":")[1]
        self.resolve = [f"{domain}:{port}:{ip}"]

    def url(self):
        ip, port = self.ipport.split(":")[0], self.ipport.split(":")[1]
        return f"{self.scheme}://{self.domain}:{port}/"

def make_easy(job: Job, timeout: float) -> pycurl.Curl:
    b = BytesIO()
    h = BytesIO()
    c = pycurl.Curl()
    c.setopt(pycurl.URL, job.url().encode('utf-8'))
    c.setopt(pycurl.WRITEDATA, b)
    c.setopt(pycurl.HEADERFUNCTION, h.write)
    c.setopt(pycurl.HTTPHEADER, [f"Host: {job.domain}", f"User-Agent: {USER_AGENT}"])
    c.setopt(pycurl.RESOLVE, job.resolve)
    c.setopt(pycurl.CONNECTTIMEOUT, timeout)
    c.setopt(pycurl.TIMEOUT, timeout)
    c.setopt(pycurl.FOLLOWLOCATION, 0)
    c.setopt(pycurl.SSL_VERIFYPEER, 0)
    c.setopt(pycurl.SSL_VERIFYHOST, 0)
    c._body_buf = b
    c._head_buf = h
    return c

# ------------- Multi runner & handler -------------
def run_multi(all_jobs: List[Job], baselines: Dict[str, Dict], max_concurrency: int, max_retries: int, timeout: int):
    multi = pycurl.CurlMulti()
    active_handles = {}
    results = []
    pending = list(all_jobs)
    seen_jobs = set()  # to avoid duplicating same ip:port+domain tests: store tuples (ipport,domain,scheme)
    in_flight = 0

    def add_next():
        nonlocal in_flight
        while pending and in_flight < max_concurrency:
            job = pending.pop(0)
            key = (job.ipport, job.domain, job.scheme)
            if key in seen_jobs:
                continue
            seen_jobs.add(key)
            easy = make_easy(job, timeout)
            multi.add_handle(easy)
            active_handles[easy] = job
            in_flight += 1

    add_next()

    while active_handles or pending:
        ret, num_handles = multi.perform()
        # collect finished handles
        while True:
            num_q, ok_list, err_list = multi.info_read()
            for c in ok_list:
                job = active_handles.pop(c, None)
                in_flight -= 1
                raw_body = c._body_buf.getvalue()
                raw_headers = c._head_buf.getvalue()
                try:
                    header_text = raw_headers.decode('iso-8859-1')
                except:
                    header_text = raw_headers.decode('utf-8', errors='replace')
                headers = {}
                for line in header_text.splitlines():
                    if ':' in line:
                        k, v = line.split(':',1)
                        headers[k.strip().lower()] = v.strip()
                status = int(c.getinfo(pycurl.RESPONSE_CODE) or 0)
                c.close()
                job.status = status
                job.headers = headers
                job.body = raw_body
                job.error = ""
                handle_completed_job(job, baselines, pending, results, max_retries, seen_jobs, timeout)
            for c, errno, errmsg in err_list:
                job = active_handles.pop(c, None)
                in_flight -= 1
                try:
                    c.close()
                except:
                    pass
                if job is None:
                    continue
                job.status = None
                job.headers = {}
                job.body = b""
                job.error = f"{errno}:{errmsg}"
                handle_completed_job(job, baselines, pending, results, max_retries, seen_jobs, timeout)
            if num_q == 0:
                break
        add_next()
        multi.select(1.0)
    return results

def handle_completed_job(job: Job, baselines: Dict[str, Dict], pending: List[Job], results: List, max_retries: int, seen_jobs: Set[Tuple], timeout: int):
    ipport = job.ipport
    baseline = baselines.get(ipport)
    if not baseline:
        return

    ip = ipport.split(":")[0]
    port = int(ipport.split(":")[1])

    # If HTTP attempt failed, try HTTPS fallback (do not count HTTP as error)
    if job.scheme == "http" and (job.status is None or job.status == 0 or (400 <= (job.status or 0) < 600 and not job.body)):
        if job.attempt <= max_retries:
            pending.append(Job(ipport, job.domain, attempt=job.attempt + 1, scheme="https"))
            return

    # If HTTP redirected to https in Location header, follow with HTTPS
    if job.scheme == "http" and job.headers.get("location","").lower().startswith("https"):
        pending.append(Job(ipport, job.domain, attempt=job.attempt, scheme="https"))
        return

    # Final attempt: compute cleaned hash and compare to baseline
    body_text = bytes_to_text(job.body)
    cleaned = clean_body(body_text, baseline["reflected_patterns"])
    normalized = norm_whitespace(cleaned)
    h = hash_text(normalized)
    different = (h != baseline["baseline_hash"])
    title = extract_title(cleaned)

    # If HTTPS and succeeded, fetch cert hostnames and handle them
    if job.scheme == "https" and job.status and job.status < 600 and job.status >= 1:
        cert_hosts = fetch_cert_hostnames(ip, port, job.domain, timeout=timeout)
        for ch in cert_hosts:
            ch = ch.strip()
            if not ch: 
                continue
            # add to results as found (wildcards included)
            # If wildcard -> record success but DO NOT baseline
            if '*' in ch:
                # wildcard success recorded only if not duplicate
                # but we also want to treat wildcard as "success" similar to other hostnames
                if (ipport, ch, 'https') not in seen_jobs:
                    # No direct probe is performed for wildcard, but we record it as success entry
                    results.append({
                        "ipport": ipport,
                        "domain": ch,
                        "scheme": "https",
                        "status": job.status,
                        "different": True,
                        "title": "",
                        "hash": "",
                        "baseline_hash": baseline["baseline_hash"],
                        "error": "cert-wildcard",
                    })
                    print(f"[+] CERT WILDCARD: {ch} {ipport}")
                    seen_jobs.add((ipport, ch, 'https'))
            else:
                # non-wildcard: treat like discovered hostname
                # ensure its escaped variants are added to reflected_patterns (so future hashes ignore them)
                for pat in escape_variants(ch):
                    baseline["reflected_patterns"].add(pat)
                # enqueue a job to test ch against this ipport (https)
                if (ipport, ch, 'https') not in seen_jobs:
                    pending.append(Job(ipport, ch, attempt=0, scheme="https"))
                    # note: the job will be added to seen_jobs when actually added to Multi in run loop

    # If it's different, print immediately and append to results list (CSV-only successes)
    if different:
        print(f"[+] DIFFERENT: {job.domain} {ipport} {title}")
        results.append({
            "ipport": ipport,
            "domain": job.domain,
            "scheme": job.scheme,
            "status": job.status,
            "different": True,
            "title": title,
            "hash": h,
            "baseline_hash": baseline["baseline_hash"],
            "error": job.error,
        })
    else:
        pass

# -------------- Start --------------
def start(domainsFile: str, ipPortsFile: str, outputCsvFilePath: str, timeout: float, retries: int, maxRequests: int):
    # load domains
    with open(domainsFile, "r", encoding="utf-8") as fh:
        domains = [line.strip() for line in fh if line.strip()]
    if not domains:
        print("No domains loaded in", domainsFile)
        return
    
    # load IP:PORTs
    with open(ipPortsFile, "r", encoding="utf-8") as fh:
        ipports = [line.strip() for line in fh if line.strip()]
    if not ipports:
        print("No IP:PORTs loaded in", ipPortsFile)
        return

    # build baselines per IP:PORT (sequential)
    print(f"[+] Building baselines for {len(ipPortsFile)} IP:PORT entries...")
    baselines = {}
    for ipport in ipports:
        print(f"    - baseline for {ipport} ...")
        b = build_baseline(ipport, BASELINE_TESTS, timeout)
        baselines[ipport] = b
        print(f"       baseline_hash={b['baseline_hash']} reflected_patterns={len(b['reflected_patterns'])}")

    # create initial jobs (http-first)
    jobs = []
    for ipport in ipports:
        for d in domains:
            jobs.append(Job(ipport, d, attempt=0, scheme="http"))

    # run multi
    print(f"[+] Running jobs: {len(jobs)} (concurrency={maxRequests})")
    start = time.time()
    results = run_multi(jobs, baselines, maxRequests, retries, timeout)
    elapsed = time.time() - start
    print(f"[+] Completed in {elapsed:.1f}s; total success records collected: {len(results)}")

    # write CSV with only successes
    fieldnames = ["ipport","domain","scheme","status","different","title","hash","baseline_hash","error"]
    try:
        with open(outputCsvFilePath, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
            w.writeheader()
            for r in results:
                w.writerow({
                    "ipport": r.get("ipport",""),
                    "domain": r.get("domain",""),
                    "scheme": r.get("scheme",""),
                    "status": r.get("status",""),
                    "different": str(r.get("different", False)),
                    "title": r.get("title",""),
                    "hash": r.get("hash",""),
                    "baseline_hash": r.get("baseline_hash",""),
                    "error": r.get("error",""),
                })
        print(f"[+] CSV written to {outputCsvFilePath}")
    except Exception as e:
        print("[!] Failed to write CSV:", e)
