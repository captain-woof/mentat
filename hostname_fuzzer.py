#!/usr/bin/env python3
"""
VHost checker library.

Call:
start(
    domainsFile=domainsFile,
    ipPortsFile=ipPortsFile,
    maxRequests=maxRequests,
    outputCsvFilePath=outputCsvFilePath,
    retries=retries,
    timeout=timeout
)
"""

from io import BytesIO
import pycurl
import ssl
import socket
import random
import string
import csv
import hashlib
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from browserforge.headers import Browser, HeaderGenerator

# ------------------ CONFIG ------------------
BROWSER = Browser(name="chrome")
BROWSER_HEADERS = HeaderGenerator(browser=BROWSER, os="windows").generate()
USER_AGENT = BROWSER_HEADERS["User-Agent"]

# Weights and thresholds (tweakable)
WEIGHT_MARKERS = 1
WEIGHT_LENGTH = 1
WEIGHT_FAVICON = 1
SCORE_THRESHOLD = 2

# Baseline and tokenisation
BASELINE_REQUESTS = 3                   # number of unique invalid-host baseline requests per ip:port
MIN_STATIC_MARKERS = 3                  # minimum stable markers required to accept baseline
TOKEN_MIN_LEN = 5                       # min token length for static marker extraction
CONTENT_LENGTH_TOLERANCE = 200          # bytes diff considered significant

# Network behavior
FOLLOW_REDIRECTS = False
VERIFY_SSL = False

# ---------------------------------------------------------------------------

_token_re = re.compile(r'[A-Za-z0-9_\-]{' + str(TOKEN_MIN_LEN) + r',}')

csv_lock = threading.Lock()
print_lock = threading.Lock()

def _random_invalid_host():
    rnd = hashlib.sha256((str(random.getrandbits(256)) + str(random.getrandbits(256))).encode()).hexdigest()[:32]
    return f"{rnd}.invalid"

def _extract_tokens(text: str):
    if not text:
        return set()
    return set(m.group(0) for m in _token_re.finditer(text))

def _make_headers_for_host(hostname: str):
    headers = []
    for k, v in BROWSER_HEADERS.items():
        headers.append(f"{k}: {v}")
    headers.append(f"Host: {hostname}")
    return headers

def _curl_request(hostname: str, ip: str, port: int, scheme: str, timeout_seconds: float, retries: int, include_body: bool = True):
    """
    Perform a single blocking pycurl request to URL built using hostname:port with resolve -> ip.
    Returns: (ok: bool, status: int, headers_dict: dict, body_bytes: bytes, error_str)
    """
    url = f"{scheme}://{hostname}:{port}/"
    resolve = [f"{hostname}:{port}:{ip}"]
    bbuf = BytesIO()
    hbuf = BytesIO()
    c = pycurl.Curl()
    try:
        c.setopt(pycurl.URL, url.encode('utf-8'))
        c.setopt(pycurl.WRITEDATA, bbuf)
        c.setopt(pycurl.HEADERFUNCTION, hbuf.write)
        c.setopt(pycurl.HTTPHEADER, _make_headers_for_host(hostname))
        c.setopt(pycurl.CONNECTTIMEOUT_MS, int(timeout_seconds * 1000))
        c.setopt(pycurl.TIMEOUT_MS, int(timeout_seconds * 1000))
        c.setopt(pycurl.NOSIGNAL, 1)
        c.setopt(pycurl.FOLLOWLOCATION, 1 if FOLLOW_REDIRECTS else 0)
        if not VERIFY_SSL:
            c.setopt(pycurl.SSL_VERIFYPEER, 0)
            c.setopt(pycurl.SSL_VERIFYHOST, 0)
        c.setopt(pycurl.SSLVERSION, pycurl.SSLVERSION_TLSv1_2)
        c.setopt(pycurl.RESOLVE, resolve)
        last_err = ""
        for attempt in range(max(1, retries)):
            try:
                c.perform()
                break
            except pycurl.error as e:
                last_err = str(e)
                if attempt == retries - 1:
                    # report failure
                    try:
                        c.close()
                    except Exception:
                        pass
                    return False, 0, {}, b"", last_err
                # else retry
        status = int(c.getinfo(pycurl.RESPONSE_CODE) or 0)
        header_bytes = hbuf.getvalue()
        try:
            header_text = header_bytes.decode('iso-8859-1')
        except Exception:
            header_text = header_bytes.decode('utf-8', errors='replace')
        headers = {}
        for line in header_text.splitlines():
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip().lower()] = v.strip()
        body = bbuf.getvalue() if include_body else b''
        try:
            c.close()
        except Exception:
            pass
        return True, status, headers, body, ""
    except Exception as e:
        try:
            c.close()
        except Exception:
            pass
        return False, 0, {}, b"", str(e)

def _fetch_cert_hostnames(ip: str, port: int, timeout_seconds: float) -> list:
    """
    Extract SAN and CN hostnames from server certificate.
    Try without SNI first, then with a random SNI to coax alternative cert if needed.
    """
    hostnames = []
    def _try(server_hostname):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout_seconds) as sock:
                # server_hostname may be None
                with ctx.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                    cert = ssock.getpeercert()
                    san = cert.get('subjectAltName', ())
                    for typ, val in san:
                        if typ and typ.lower() == 'dns' and val:
                            hostnames.append(val)
                    subj = cert.get('subject', ())
                    for part in subj:
                        for k, v in part:
                            if k == 'commonName' and v:
                                hostnames.append(v)
            return True
        except Exception:
            return False
    # Try without SNI
    _try(None)
    # Try with a random SNI to get alternate cert if server differentiates
    _try(_random_invalid_host())
    # Deduplicate preserving order
    out = []
    for h in hostnames:
        if h and h not in out:
            out.append(h)
    return out

def _build_baseline_for_ipport(ip: str, port: int, timeout_seconds: float, retries: int):
    """
    Build baseline signature for ip:port.
    Returns dict or None on failure/insufficient baseline.
    Dict contains:
      - static_markers: set(str)
      - baseline_length: int (avg)
      - baseline_location: str
      - baseline_favicon_hash: str or None
      - cert_hostnames: list
    """
    cert_hostnames = _fetch_cert_hostnames(ip, port, timeout_seconds)

    # perform BASELINE_REQUESTS with distinct invalid hostnames concurrently
    contents = []
    statuses = []
    locations = []
    with ThreadPoolExecutor(max_workers=BASELINE_REQUESTS) as bex:
        futures = [bex.submit(_curl_request, _random_invalid_host(), ip, port, scheme, timeout_seconds, retries, True)
                   for scheme in ["http", "https"][:1]]  # placeholder, we'll loop per invalid host directly
    # Instead of above (kept for clarity), do direct parallel invalid-host fetches:
    with ThreadPoolExecutor(max_workers=BASELINE_REQUESTS) as bex:
        inv_futures = []
        for _ in range(BASELINE_REQUESTS):
            inv_host = _random_invalid_host()
            # schedule http-first then https fallback inside worker function
            inv_futures.append(bex.submit(_baseline_fetch_http_then_https, inv_host, ip, port, timeout_seconds, retries))
        for fut in as_completed(inv_futures):
            ok, status, headers, body = fut.result()
            if ok:
                contents.append(body.decode('utf-8', errors='replace'))
                statuses.append(status)
                loc = headers.get('location', '').strip() if headers else ''
                if loc:
                    locations.append(loc)
    if len(contents) < 2:
        return None

    # extract static markers as intersection of tokens across contents (case-sensitive tokens)
    token_sets = [_extract_tokens(c) for c in contents]
    static_markers = set.intersection(*token_sets) if token_sets else set()

    # minimal baseline hygiene
    total_marker_chars = sum(len(m) for m in static_markers)
    if len(static_markers) < MIN_STATIC_MARKERS or total_marker_chars < (TOKEN_MIN_LEN * MIN_STATIC_MARKERS):
        return None

    avg_length = int(sum(len(c.encode('utf-8')) for c in contents) / len(contents)) if contents else 0
    baseline_location = locations[0] if locations else ""

    # baseline favicon: fetch once with random invalid host to avoid caches
    fav_hash = _fetch_favicon_for_host(ip, port, _random_invalid_host(), timeout_seconds, retries)

    return {
        "static_markers": static_markers,
        "baseline_length": avg_length,
        "baseline_location": baseline_location,
        "baseline_favicon": fav_hash,
        "cert_hostnames": cert_hostnames,
    }

def _baseline_fetch_http_then_https(inv_host: str, ip: str, port: int, timeout_seconds: float, retries: int):
    """
    Helper used by baseline building: try HTTP then HTTPS for an invalid host.
    Returns (ok, status, headers_dict, body_bytes).
    """
    ok, status, headers, body, err = _curl_request(inv_host, ip, port, "http", timeout_seconds, retries, include_body=True)
    if not ok or (status and 400 <= status < 600 and not body):
        ok, status, headers, body, err = _curl_request(inv_host, ip, port, "https", timeout_seconds, retries, include_body=True)
    return ok, status, headers, body

def _fetch_favicon_for_host(ip: str, port: int, hostname: str, timeout_seconds: float, retries: int):
    """
    Fetch /favicon.ico for given hostname mapping to ip:port. Returns sha256 hex or None.
    """
    ok, status, headers, body, err = _curl_request(hostname, ip, port, "http", timeout_seconds, retries, include_body=True)
    if not ok or (status and 400 <= status < 600 and not body):
        ok, status, headers, body, err = _curl_request(hostname, ip, port, "https", timeout_seconds, retries, include_body=True)
    if ok and body:
        return hashlib.sha256(body).hexdigest()
    return None

def _extract_cert_exact_matches(cert_hostnames):
    """
    Return set of exact-match (non-wildcard) hostnames from cert list.
    """
    out = set()
    for h in cert_hostnames:
        if not h:
            continue
        if '*' not in h:
            out.add(h)
    return out

def _test_candidate(ip: str, port: int, domain: str, baseline_future, timeout_seconds: float, retries: int):
    """
    Perform candidate test: waits for baseline_future, then executes full checks.
    Returns result dict on success or None.
    """
    try:
        baseline = baseline_future.result()
        if not baseline:
            return None
        # cert exact-match check
        certs = baseline.get("cert_hostnames", []) or []
        exact_set = _extract_cert_exact_matches(certs)
        if domain in exact_set:
            # trusted by cert; attempt quick title fetch via https for display
            ok, status, headers, body, err = _curl_request(domain, ip, port, "https", timeout_seconds, retries, include_body=True)
            title = ""
            if ok and body:
                try:
                    title = re.search(r'<title[^>]*>(.*?)</title>', body.decode('utf-8', errors='ignore'), re.IGNORECASE | re.DOTALL)
                    title = title.group(1).strip() if title else ""
                except Exception:
                    title = ""
            return {"ipport": f"{ip}:{port}", "domain": domain, "scheme": "https", "status": status, "title": title, "reason": "cert-exact"}

        # perform http-first then https fallback for page
        ok, status, headers, body, err = _curl_request(domain, ip, port, "http", timeout_seconds, retries, include_body=True)
        used_scheme = "http"
        if (not ok) or (status and 400 <= status < 600 and not body):
            ok, status, headers, body, err = _curl_request(domain, ip, port, "https", timeout_seconds, retries, include_body=True)
            if ok:
                used_scheme = "https"
        if not ok:
            return None

        body_text = body.decode('utf-8', errors='ignore')
        score = 0

        # static markers presence
        static_markers = baseline["static_markers"]
        if static_markers:
            match_count = 0
            for m in static_markers:
                if m and m in body_text:
                    match_count += 1
            match_ratio = match_count / len(static_markers) if static_markers else 0.0
            # if many markers missing (match_ratio < 0.95) => different
            if match_ratio < 0.95:
                score += WEIGHT_MARKERS
        else:
            # if baseline had none (should not happen), treat as inconclusive -> don't increase
            pass

        # content length
        baseline_len = baseline.get("baseline_length", 0)
        if abs(len(body) - baseline_len) > CONTENT_LENGTH_TOLERANCE:
            score += WEIGHT_LENGTH

        # location header difference
        baseline_loc = baseline.get("baseline_location", "")
        candidate_loc = headers.get('location', '').strip() if headers else ""
        if bool(candidate_loc) != bool(baseline_loc):
            score += 0  # leave this criterion out of scoring per final weights (kept simple)
        else:
            if candidate_loc and baseline_loc and candidate_loc != baseline_loc:
                score += 0

        # favicon compare
        baseline_fav = baseline.get("baseline_favicon", None)
        cand_fav = _fetch_favicon_for_host(ip, port, domain, timeout_seconds, retries)
        if baseline_fav is None and cand_fav is not None:
            score += WEIGHT_FAVICON
        elif baseline_fav is not None and cand_fav is None:
            score += WEIGHT_FAVICON
        elif baseline_fav is not None and cand_fav is not None and baseline_fav != cand_fav:
            score += WEIGHT_FAVICON

        if score >= SCORE_THRESHOLD:
            # extract title
            try:
                title_m = re.search(r'<title[^>]*>(.*?)</title>', body_text, re.IGNORECASE | re.DOTALL)
                title = title_m.group(1).strip() if title_m else ""
            except Exception:
                title = ""
            return {"ipport": f"{ip}:{port}", "domain": domain, "scheme": used_scheme, "status": status, "title": title, "reason": "score", "score": score}
        return None
    except Exception:
        return None

def start(domainsFile, ipPortsFile, maxRequests, outputCsvFilePath, retries, timeout):
    """
    Main entry point.
    """
    # load domains
    with open(domainsFile, 'r', encoding='utf-8') as fh:
        domains = [line.strip() for line in fh if line.strip()]

    # load ip:port list
    ipports = []
    with open(ipPortsFile, 'r', encoding='utf-8') as fh:
        for line in fh:
            s = line.strip()
            if not s:
                continue
            if ':' in s:
                ip, port = s.split(':', 1)
                ipports.append((ip.strip(), int(port.strip())))

    # prepare CSV and locks
    csv_file = open(outputCsvFilePath, 'w', newline='', encoding='utf-8')
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(["ipport", "domain", "scheme", "status", "title", "reason"])

    executor = ThreadPoolExecutor(max_workers=maxRequests)
    try:
        # schedule baseline building + certificate extraction per ip:port
        baseline_futures = {}
        for ip, port in ipports:
            with print_lock:
                print(f"[+] scheduling baseline for {ip}:{port}")
            fut = executor.submit(_build_baseline_for_ipport, ip, port, timeout, retries)
            baseline_futures[(ip, port)] = fut

        # schedule candidate tests immediately (they will wait on baseline futures)
        candidate_futures = {}
        for ip, port in ipports:
            fut_baseline = baseline_futures.get((ip, port))
            for domain in domains:
                f = executor.submit(_test_candidate, ip, port, domain, fut_baseline, timeout, retries)
                candidate_futures[f] = (ip, port, domain)

        # process completed candidate futures and write successes
        for fut in as_completed(candidate_futures):
            res = None
            try:
                res = fut.result()
            except Exception:
                res = None
            if res:
                with print_lock:
                    print(f"[+] MATCH: {res['domain']} {res['ipport']} {res.get('title','')}")
                with csv_lock:
                    csv_writer.writerow([res['ipport'], res['domain'], res['scheme'], res.get('status',''), res.get('title',''), res.get('reason','')])

        # also accept exact cert matches (some baselines include cert hostnames)
        # If any baseline futures included cert hostnames, write exact non-wildcard cert hostnames as successes
        for (ip, port), bf in baseline_futures.items():
            try:
                baseline = bf.result()
                if not baseline:
                    continue
                cert_names = baseline.get("cert_hostnames", []) or []
                for ch in cert_names:
                    if ch and '*' not in ch:
                        # quick title attempt via https
                        ok, status, headers, body, err = _curl_request(ch, ip, port, "https", timeout, retries, include_body=True)
                        title = ""
                        if ok and body:
                            try:
                                title_m = re.search(r'<title[^>]*>(.*?)</title>', body.decode('utf-8', errors='ignore'), re.IGNORECASE | re.DOTALL)
                                title = title_m.group(1).strip() if title_m else ""
                            except Exception:
                                title = ""
                        with print_lock:
                            print(f"[+] CERT MATCH: {ch} {ip}:{port} {title}")
                        with csv_lock:
                            csv_writer.writerow([f"{ip}:{port}", ch, "https", status or "", title, "cert-exact"])
            except Exception:
                continue
    finally:
        executor.shutdown(wait=True)
        csv_file.close()
