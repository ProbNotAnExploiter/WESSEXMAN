import socket, requests, ssl, subprocess, sys, threading, re, hashlib, os, urllib
from bs4 import BeautifulSoup
from main import COMMON_PORTS, clear
from rich.console import Console

TIMEOUT = 10
sys.stdout.reconfigure(encoding="utf-8")
console = Console()


def sanitize(data):
    if isinstance(data, bytes):
        return data.decode("utf-8", "replace")
    if isinstance(data, str):
        return data.encode("utf-8", "replace").decode("utf-8")
    return str(data)


def parse_tagged_input(text: str):
    result = {}
    parts = re.split(r"\s(?=\w+:)", text)

    for part in parts:
        if ":" in part:
            key, value = part.split(":", 1)
            result[key.lower()] = value.strip()

    return result


def get_text(r):
    try:
        return r.content.decode("utf-8", "replace")
    except:
        return r.text.encode("utf-8", "replace").decode("utf-8")


def cldomain(domain):
    domain = domain.encode("utf-8", "ignore").decode("utf-8")
    domain = re.sub(r"[^a-zA-Z0-9.-]", "", domain)
    return domain.strip().lower()


def clinput(s):
    return s.encode("utf-8", "ignore").decode("utf-8")


def http_get(url, timeout=10, **kwargs):
    return requests.get(url, timeout=timeout, **kwargs)


def ok(msg):
    return f"[+] " + sanitize(msg)


def wr(msg):
    return "[!] " + sanitize(msg)


def err(msg):
    return f"[-] " + sanitize(msg)


def sk(msg):
    return f"[~] " + sanitize(msg)


def cmd_exists(cmd):
    return (
        subprocess.call(
            ["which", cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        == 0
    )


import requests


def geocode(query):
    url = "https://nominatim.openstreetmap.org/search"
    params = {"q": query, "format": "json", "limit": 1}
    headers = {"User-Agent": "osint-tool"}
    r = requests.get(url, params=params, headers=headers)
    return r.json()


def run_cmd(cmd, timeout=20):
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate(timeout=timeout)

        return (sanitize(out), sanitize(err), p.returncode)
    except Exception as e:
        return "", sanitize(str(e)), -1


# ── [01] DNS A Records ────────────────────────────────────────────────────
def t01_dns_a(t):
    if t["is_ip"]:
        return sk("Target is IP — skipping A record lookup")
    try:
        res = socket.getaddrinfo(t["domain"], None, socket.AF_INET)
        ips = sorted(set(r[4][0] for r in res))
        return ok("A Records: " + ", ".join(ips))
    except Exception as ex:
        # fallback: dig
        out, _, rc = run_cmd(["dig", "+short", "A", t["domain"]], 15)
        if rc == 0 and out.strip():
            return ok("A Records:\n" + out.strip())
        return err(str(ex))


# ── [02] DNS MX Records ───────────────────────────────────────────────────
def t02_dns_mx(t):
    if t["is_ip"]:
        return sk("N/A for IP")
    out, _, rc = run_cmd(["dig", "MX", t["domain"], "+short"], 15)
    if rc == 0 and out.strip():
        return ok("MX Records:\n" + out.strip())
    out2, _, rc2 = run_cmd(["nslookup", "-type=MX", t["domain"]], 15)
    if rc2 == 0 and "mail exchanger" in out2.lower():
        return ok("MX Records:\n" + out2.strip())
    return wr("No MX records found or dig/nslookup unavailable")


# ── [03] DNS NS Records ───────────────────────────────────────────────────
def t03_dns_ns(t):
    if t["is_ip"]:
        return sk("N/A for IP")
    out, _, rc = run_cmd(["dig", "NS", t["domain"], "+short"], 15)
    if rc == 0 and out.strip():
        return ok("NS Records:\n" + out.strip())
    out2, _, _ = run_cmd(["nslookup", "-type=NS", t["domain"]], 15)
    return (
        ok("NS Records:\n" + out2.strip())
        if "nameserver" in out2.lower()
        else wr("No NS records found")
    )


# ── [04] DNS TXT Records ──────────────────────────────────────────────────
def t04_dns_txt(t):
    if t["is_ip"]:
        return sk("N/A for IP")
    out, _, rc = run_cmd(["dig", "TXT", t["domain"], "+short"], 15)
    if rc == 0 and out.strip():
        return ok("TXT Records (SPF/DKIM/DMARC):\n" + out.strip())
    return wr("No TXT records found")


# ── [05] DNS AAAA (IPv6) Records ──────────────────────────────────────────
def t05_dns_aaaa(t):
    if t["is_ip"]:
        return sk("N/A for IP")
    out, _, rc = run_cmd(["dig", "AAAA", t["domain"], "+short"], 15)
    if rc == 0 and out.strip():
        return ok("AAAA (IPv6) Records:\n" + out.strip())
    try:
        res = socket.getaddrinfo(t["domain"], None, socket.AF_INET6)
        ips = sorted(set(r[4][0] for r in res))
        return ok("IPv6: " + ", ".join(ips))
    except:
        return wr("No IPv6 records found")


# ── [06] DNS CNAME Records ────────────────────────────────────────────────
def t06_dns_cname(t):
    if t["is_ip"]:
        return sk("N/A for IP")
    out, _, rc = run_cmd(["dig", "CNAME", t["domain"], "+short"], 15)
    if rc == 0 and out.strip():
        return ok("CNAME: " + out.strip())
    return wr("No CNAME record found")


# ── [07] Reverse DNS (PTR) ────────────────────────────────────────────────
def t07_reverse_dns(t):
    ip = t["ip"]
    if not ip:
        return err("No IP resolved for reverse DNS")
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return ok(f"Reverse DNS: {ip}  →  {host}")
    except socket.herror:
        return wr(f"No PTR record for {ip}")
    except Exception as ex:
        return err(str(ex))


# ── [08] Zone Transfer Attempt ────────────────────────────────────────────
def t08_zone_transfer(t):
    if t["is_ip"]:
        return sk("N/A for IP")
    domain = t["domain"]
    out_ns, _, _ = run_cmd(["dig", "NS", domain, "+short"], 15)
    ns_list = [x.rstrip(".") for x in out_ns.strip().split("\n") if x.strip()]
    if not ns_list:
        return wr("Could not retrieve NS records — zone transfer skipped")
    results = []
    for ns in ns_list[:4]:
        out, _, rc = run_cmd(["dig", "AXFR", f"@{ns}", domain], 20)
        if rc == 0 and len(out) > 300 and "Transfer failed" not in out:
            results.append(f"{ns}: !! ZONE TRANSFER POSSIBLE !!\n{out[:500]}")
        else:
            results.append(f"{ns}: Transfer denied ✓")
    return ok("\n".join(results))


# ── [09] WHOIS / RDAP ─────────────────────────────────────────────────────
def t09_whois_rdap(t):
    target = t["ip"] if t["is_ip"] else t["domain"]
    # Try system whois
    if cmd_exists("whois"):
        out, _, rc = run_cmd(["whois", target], 30)
        if rc == 0 and len(out.strip()) > 50:
            keep_keys = [
                "registrar",
                "created",
                "expir",
                "updated",
                "name server",
                "organization",
                "country",
                "netname",
                "cidr",
                "abuse",
                "email",
                "org-name",
                "owner",
                "admin",
                "tech",
                "registrant",
                "status",
                "dnssec",
            ]
            lines = [
                l
                for l in out.split("\n")
                if any(k in l.lower() for k in keep_keys) and ":" in l
            ]
            return ok("\n".join(lines[:40]) if lines else out[:1500])
    # Fallback: RDAP API
    try:
        if t["is_ip"]:
            r = http_get(f"https://rdap.arin.net/registry/ip/{target}")
        else:
            r = http_get(f"https://rdap.verisign.com/com/v1/domain/{target}")
        if r.status_code == 200:
            d = r.json()
            info = [
                f"Handle:  {d.get('handle','N/A')}",
                f"Name:    {d.get('name','N/A')}",
                f"Type:    {d.get('type','N/A')}",
            ]
            for ev in d.get("events", [])[:5]:
                info.append(
                    f"{ev.get('eventAction','')}: {ev.get('eventDate','')[:10]}"
                )
            return ok("\n".join(info))
    except Exception as ex:
        return err(f"RDAP failed: {ex}")
    return err("whois/RDAP unavailable")


# ── [10] IP Geolocation (ip-api.com) ─────────────────────────────────────
def t10_ip_geoloc(t):
    ip = t["ip"]
    if not ip:
        return err("No IP resolved")
    try:
        fields = "status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        r = http_get(f"http://ip-api.com/json/{ip}?fields={fields}")
        if r.status_code == 200:
            d = r.json()
            if d.get("status") == "success":
                return ok(
                    f"IP:        {d.get('query')}\n"
                    f"Country:   {d.get('country')} ({d.get('countryCode','')})\n"
                    f"Region:    {d.get('regionName')}\n"
                    f"City:      {d.get('city')} {d.get('zip','')}\n"
                    f"Coords:    {d.get('lat')}, {d.get('lon')}\n"
                    f"Timezone:  {d.get('timezone')}\n"
                    f"ISP:       {d.get('isp')}\n"
                    f"Org:       {d.get('org')}\n"
                    f"ASN:       {d.get('as')}"
                )
            return wr(d.get("message", "Rate limited or private IP"))
    except Exception as ex:
        return err(str(ex))
    return err("ip-api.com request failed")


# ── [11] IPInfo.io ────────────────────────────────────────────────────────
def t11_ipinfo(t):
    ip = t["ip"]
    if not ip:
        return err("No IP resolved")
    try:
        r = http_get(f"https://ipinfo.io/{ip}/json")
        if r.status_code == 200:
            d = r.json()
            if d.get("bogon"):
                return wr(f"Bogon/private IP: {ip}")
            return ok(
                f"IP:       {d.get('ip')}\n"
                f"Hostname: {d.get('hostname','N/A')}\n"
                f"City:     {d.get('city','N/A')}\n"
                f"Region:   {d.get('region','N/A')}\n"
                f"Country:  {d.get('country','N/A')}\n"
                f"Org:      {d.get('org','N/A')}\n"
                f"Postal:   {d.get('postal','N/A')}\n"
                f"Timezone: {d.get('timezone','N/A')}"
            )
    except Exception as ex:
        return err(str(ex))
    return err("ipinfo.io request failed")


# ── [12] Shodan InternetDB (free, no key) ────────────────────────────────
def t12_shodan_idb(t):
    ip = t["ip"]
    if not ip:
        return err("No IP resolved")
    try:
        r = http_get(f"https://internetdb.shodan.io/{ip}")
        if r.status_code == 200:
            d = r.json()
            if "detail" in d:
                return wr(str(d["detail"]))
            ports = ", ".join(str(p) for p in d.get("ports", []))
            hosts = ", ".join(d.get("hostnames", [])[:5])
            cpes = ", ".join(d.get("cpes", [])[:5])
            vulns = ", ".join(d.get("vulns", [])[:10])
            tags = ", ".join(d.get("tags", []))
            return ok(
                f"IP:        {d.get('ip')}\n"
                f"Open Ports:{ports or 'none'}\n"
                f"Hostnames: {hosts or 'none'}\n"
                f"CPEs:      {cpes  or 'none'}\n"
                f"Tags:      {tags  or 'none'}\n"
                f"Vulns:     {vulns or 'none'}"
            )
        return wr(f"HTTP {r.status_code}")
    except Exception as ex:
        return err(str(ex))


# ── [13] BGP / ASN Info (BGPView) ────────────────────────────────────────
def t13_bgp_asn(t):
    ip = t["ip"]
    if not ip:
        return err("No IP resolved")
    try:
        r = http_get(f"https://api.bgpview.io/ip/{ip}")
        if r.status_code == 200:
            data = r.json().get("data", {})
            pfxs = data.get("prefixes", [])
            lines = [f"IP: {ip}"]
            for pfx in pfxs[:3]:
                for asn in pfx.get("asns", [])[:2]:
                    lines += [
                        f"ASN:      {asn.get('asn')} — {asn.get('name','')}",
                        f"Country:  {asn.get('country_code','')}",
                        f"Prefix:   {pfx.get('prefix','')}",
                        f"RIR:      {pfx.get('rir_allocation',{}).get('rir_name','')}",
                        f"Desc:     {pfx.get('description','')}",
                        "---",
                    ]
            return (
                ok("\n".join(lines)) if len(lines) > 1 else wr("No BGP/ASN data found")
            )
    except Exception as ex:
        return err(str(ex))
    return err("BGPView request failed")


# ── [14] GreyNoise Community ──────────────────────────────────────────────
def t14_greynoise(t):
    ip = t["ip"]
    if not ip:
        return err("No IP resolved")
    try:
        r = http_get(f"https://api.greynoise.io/v3/community/{ip}")
        if r.status_code == 200:
            d = r.json()
            return ok(
                f"IP:      {d.get('ip')}\n"
                f"Noise:   {d.get('noise')}\n"
                f"Riot:    {d.get('riot')}\n"
                f"Name:    {d.get('name','N/A')}\n"
                f"Message: {d.get('message','')}\n"
                f"Link:    {d.get('link','')}"
            )
        if r.status_code == 404:
            return wr("IP not in GreyNoise dataset (not seen scanning the internet)")
        return wr(f"HTTP {r.status_code}: {r.text[:200]}")
    except Exception as ex:
        return err(str(ex))


# ── [15] AbuseIPDB (public lookup) ───────────────────────────────────────
def t15_abuseipdb(t):
    ip = t["ip"]
    if not ip:
        return err("No IP resolved")
    try:
        r = http_get(
            f"https://www.abuseipdb.com/check/{ip}",
            headers={"User-Agent": "Mozilla/5.0 (OSINT/1.0)"},
        )
        if r.status_code == 200:
            txt = r.text
            score_m = re.search(r"(\d+)\s*%", txt)
            report_m = re.search(r"(\d[\d,]*)\s+report", txt, re.I)
            country_m = re.search(r'country["\s:]+([A-Z]{2})', txt, re.I)
            score = score_m.group(1) + "%" if score_m else "N/A"
            reports = report_m.group(1) if report_m else "N/A"
            country = country_m.group(1) if country_m else "N/A"
            return ok(
                f"AbuseIPDB  →  {ip}\n"
                f"Abuse Score: {score}\n"
                f"Reports:     {reports}\n"
                f"Country:     {country}\n"
                f"Details:     https://www.abuseipdb.com/check/{ip}"
            )
        return wr(f"HTTP {r.status_code}")
    except Exception as ex:
        return err(str(ex))


# ── [16] ThreatCrowd ─────────────────────────────────────────────────────
def t16_threatcrowd(t):
    try:
        if t["is_ip"]:
            url = f"https://www.threatcrowd.org/searchApi/v2/ip/report/?ip={t['ip']}"
        else:
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={t['domain']}"
        r = http_get(url)
        if r.status_code == 200:
            d = r.json()
            lines = [f"Response Code: {d.get('response_code','N/A')}"]
            if d.get("resolutions"):
                lines.append(f"Resolutions ({len(d['resolutions'])}):")
                for res in d["resolutions"][:8]:
                    lines.append(
                        f"  → {res.get('ip_address', res.get('domain',''))} "
                        f"({res.get('last_resolved','')[:10]})"
                    )
            if d.get("hashes"):
                lines.append(f"Related malware hashes: {len(d['hashes'])}")
            if d.get("emails"):
                lines.append(f"Emails: {', '.join(d['emails'][:5])}")
            if d.get("votes") is not None:
                lines.append(f"Malicious votes: {d['votes']}")
            return ok("\n".join(lines))
        return wr(f"HTTP {r.status_code}")
    except Exception as ex:
        return err(str(ex))


# ── [17] crt.sh Certificate Transparency ─────────────────────────────────
def t17_crtsh(t):
    if t["is_ip"]:
        return sk("N/A for IP addresses")
    domain = t["domain"]
    try:
        r = http_get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=20)
        if r.status_code == 200:
            data = r.json()
            subs = set()
            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if name and domain in name:
                        subs.add(name)
            if subs:
                sorted_subs = sorted(subs)
                return ok(
                    f"crt.sh found {len(sorted_subs)} subdomains:\n"
                    + "\n".join(sorted_subs[:60])
                )
            return wr("No certificates found in crt.sh")
    except Exception as ex:
        return err(str(ex))
    return err("crt.sh request failed")


# ── [18] HackerTarget DNS / DNSDumpster ──────────────────────────────────
def t18_dnsdumpster(t):
    if t["is_ip"]:
        return sk("N/A for IP")
    domain = t["domain"]
    try:
        r = http_get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=20)
        if r.status_code == 200:
            txt = r.text.strip()
            if "error" in txt.lower() or "API" in txt:
                return wr(f"HackerTarget: {txt[:200]}")
            lines = txt.split("\n")
            hosts = []
            for line in lines:
                if "," in line:
                    host, ip_addr = line.split(",", 1)
                    hosts.append(f"  {host.strip():<45} {ip_addr.strip()}")
            return ok(
                f"HackerTarget — {len(hosts)} DNS records:\n" + "\n".join(hosts[:40])
            )
    except Exception as ex:
        return err(str(ex))
    return err("HackerTarget request failed")


# ── [19] HTTP Headers Analysis ───────────────────────────────────────────
def t19_http_headers(t):
    for url in [t["url"], f"https://{t['host']}"]:
        try:
            r = http_get(url, allow_redirects=True)
            lines = [
                f"Status:    {r.status_code} {r.reason}",
                f"Final URL: {r.url}",
                "─" * 45,
            ]
            for k, v in r.headers.items():
                lines.append(f"{k}: {v}")
            return ok("\n".join(lines))
        except requests.exceptions.SSLError:
            continue
        except Exception as ex:
            last_err = str(ex)
    return err(last_err)


# ── [20] SSL Certificate Info ─────────────────────────────────────────────
def t20_ssl_cert(t):
    host = t["host"]
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        sans = cert.get("subjectAltName", [])
        lines = [
            f"Subject CN:  {subject.get('commonName','N/A')}",
            f"Subject Org: {subject.get('organizationName','N/A')}",
            f"Issuer:      {issuer.get('organizationName','N/A')} ({issuer.get('countryName','')})",
            f"Valid From:  {cert.get('notBefore','N/A')}",
            f"Valid To:    {cert.get('notAfter','N/A')}",
            f"Cipher:      {cipher[0]} ({cipher[1]} bit)" if cipher else "",
            f"SANs ({len(sans)}): {', '.join(v for _,v in sans[:10])}",
        ]
        return ok("\n".join(l for l in lines if l))
    except ssl.SSLError as ex:
        return wr(f"SSL error: {ex}")
    except ConnectionRefusedError:
        return wr("Port 443 closed — no SSL service detected")
    except Exception as ex:
        return err(str(ex))


# ── [21] Security Headers Audit ──────────────────────────────────────────
def t21_security_headers(t):
    try:
        r = http_get(t["url"])
        h = {k.lower(): v for k, v in r.headers.items()}
        checks = {
            "strict-transport-security": "HSTS",
            "content-security-policy": "CSP",
            "x-frame-options": "X-Frame-Options",
            "x-xss-protection": "X-XSS-Protection",
            "x-content-type-options": "X-Content-Type-Options",
            "referrer-policy": "Referrer-Policy",
            "permissions-policy": "Permissions-Policy",
        }
        present, missing = [], []
        for header, name in checks.items():
            if header in h:
                present.append(f"  [PRESENT] {name}: {h[header][:80]}")
            else:
                missing.append(f"  [MISSING] {name}")
        score = len(present)
        grade = "A" if score >= 6 else "B" if score >= 4 else "C" if score >= 2 else "F"
        lines = [f"Security Headers Audit — Grade: {grade} ({score}/7 headers present)"]
        lines += present + missing
        return ok("\n".join(lines))
    except Exception as ex:
        return err(str(ex))


# ── [22] CORS Misconfiguration ───────────────────────────────────────────
def t22_cors_check(t):
    try:
        r = http_get(
            t["url"],
            headers={"Origin": "https://evil-site.com", "User-Agent": "Mozilla/5.0"},
        )
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        acam = r.headers.get("Access-Control-Allow-Methods", "")
        lines = [
            f"Allow-Origin:      {acao or 'Not set'}",
            f"Allow-Credentials: {acac or 'Not set'}",
            f"Allow-Methods:     {acam or 'Not set'}",
            "─" * 40,
        ]
        if acao == "*":
            lines.append("⚠ WARNING: Wildcard (*) CORS — any origin allowed")
        elif "evil-site.com" in acao:
            lines.append(
                "⚠ CRITICAL: Reflects arbitrary Origin (CORS hijack possible!)"
            )
        elif acao and acac.lower() == "true":
            lines.append("⚠ WARNING: Credentialed CORS with reflected origin")
        else:
            lines.append("✓ CORS appears properly configured")
        return ok("\n".join(lines))
    except Exception as ex:
        return err(str(ex))


# ── [23] robots.txt ───────────────────────────────────────────────────────
def t23_robots_txt(t):
    url = t["url"].rstrip("/") + "/robots.txt"
    try:
        r = http_get(url)
        if r.status_code == 200 and len(r.text.strip()) > 5:
            lines = r.text.strip().split("\n")
            disallowed = [l for l in lines if l.lower().startswith("disallow")]
            return ok(
                f"robots.txt found ({len(lines)} lines, {len(disallowed)} Disallow entries):\n{r.text[:2000]}"
            )
        return wr(f"HTTP {r.status_code} — robots.txt not found or empty")
    except Exception as ex:
        return err(str(ex))


# ── [24] sitemap.xml ─────────────────────────────────────────────────────
def t24_sitemap(t):
    base = t["url"].rstrip("/")
    for path in ["/sitemap.xml", "/sitemap_index.xml", "/sitemap.txt", "/sitemap"]:
        try:
            r = http_get(base + path, timeout=8)
            if r.status_code == 200 and len(r.text.strip()) > 20:
                url_count = r.text.count("<url>")
                loc_count = r.text.count("<loc>")
                return ok(
                    f"Sitemap found: {base + path}\n"
                    f"<url> entries:  {url_count}\n"
                    f"<loc> entries:  {loc_count}\n"
                    f"Preview:\n{r.text[:600]}"
                )
        except:
            pass
    return wr("No sitemap.xml found at common paths")


# ── [25] Wayback Machine ──────────────────────────────────────────────────
def t25_wayback(t):
    domain = t["domain"]
    try:
        r = http_get(f"https://archive.org/wayback/available?url={domain}", timeout=15)
        if r.status_code == 200:
            snap = r.json().get("archived_snapshots", {}).get("closest", {})
            if snap:
                return ok(
                    f"Wayback Machine snapshot found!\n"
                    f"URL:       {snap.get('url')}\n"
                    f"Timestamp: {snap.get('timestamp')}\n"
                    f"Status:    {snap.get('status')}\n"
                    f"More:      https://web.archive.org/web/*/{domain}"
                )
            return wr(f"No Wayback Machine snapshots for {domain}")
    except Exception as ex:
        return err(str(ex))
    return err("Wayback request failed")


# ── [26] VirusTotal (public lookup) ──────────────────────────────────────
def t26_virustotal(t):
    target = t["domain"] if not t["is_ip"] else t["ip"]
    try:
        r = http_get(
            f"https://www.virustotal.com/ui/search?query={target}&limit=5",
            headers={
                "x-tool": "vt-ui-main",
                "User-Agent": "Mozilla/5.0",
                "Accept": "application/json",
            },
        )
        if r.status_code == 200:
            items = r.json().get("data", [])
            if items:
                attrs = items[0].get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                rep = attrs.get("reputation", "N/A")
                cats = attrs.get("categories", {})
                return ok(
                    f"VirusTotal → {target}\n"
                    f"Malicious:  {stats.get('malicious',0)}\n"
                    f"Suspicious: {stats.get('suspicious',0)}\n"
                    f"Harmless:   {stats.get('harmless',0)}\n"
                    f"Undetected: {stats.get('undetected',0)}\n"
                    f"Reputation: {rep}\n"
                    f"Categories: {', '.join(list(cats.values())[:3])}"
                )
        return wr(
            f"VT HTTP {r.status_code} — visit: https://www.virustotal.com/gui/search/{target}"
        )
    except Exception as ex:
        return err(str(ex))


# ── [27] URLScan.io ───────────────────────────────────────────────────────
def t27_urlscan(t):
    domain = t["domain"]
    try:
        r = http_get(
            f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=5", timeout=15
        )
        if r.status_code == 200:
            d = r.json()
            total = d.get("total", 0)
            results = d.get("results", [])
            lines = [f"URLScan.io — {total} scans found for: {domain}"]
            for res in results[:5]:
                page = res.get("page", {})
                ts = res.get("task", {}).get("time", "")[:10]
                lines.append(
                    f"  [{ts}] {page.get('url','')[:70]}  [{page.get('status','')}]"
                )
            if total:
                lines.append(
                    f"  Full results: https://urlscan.io/search/#domain:{domain}"
                )
            return ok("\n".join(lines))
        return wr(f"HTTP {r.status_code}")
    except Exception as ex:
        return err(str(ex))


# ── [28] Ping ─────────────────────────────────────────────────────────────
def t28_ping(t):
    host = t["host"]
    flag = "-n" if os.name == "nt" else "-c"
    out, _, rc = run_cmd(["ping", flag, "4", "-W", "2", host], 20)
    if rc == 0:
        m = re.search(r"(?:avg|rtt)[^=]+=\s*[\d.]+/([\d.]+)", out)
        avg = (m.group(1) + " ms") if m else "see output"
        return ok(f"Host is REACHABLE | Avg RTT: {avg}\n{out.strip()}")
    return wr(f"Host appears DOWN or ICMP filtered\n{out.strip()}")


# ── [29] Traceroute ───────────────────────────────────────────────────────
def t29_traceroute(t):
    host = t["host"]
    if cmd_exists("traceroute"):
        out, _, rc = run_cmd(["traceroute", "-m", "20", "-w", "2", host], 90)
    elif cmd_exists("tracert"):
        out, _, rc = run_cmd(["tracert", "-h", "20", host], 90)
    else:
        return sk("traceroute/tracert not installed  (pkg install traceroute)")
    if out.strip():
        return ok(f"Traceroute → {host}:\n{out[:2500]}")
    return wr("Traceroute produced no output")


# ── [30] Banner Grabbing ─────────────────────────────────────────────────
def t30_banner_grab(t):
    ip = t["ip"] or t["host"]
    probes = {
        21: b"",
        22: b"",
        25: b"",
        80: b"HEAD / HTTP/1.0\r\nHost: " + t["host"].encode() + b"\r\n\r\n",
        110: b"",
        143: b"",
        443: None,  # skip, SSL handled
        8080: b"HEAD / HTTP/1.0\r\n\r\n",
    }
    results = []
    for port, probe in probes.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            if s.connect_ex((ip, port)) == 0:
                if probe is not None:
                    if probe:
                        s.send(probe)
                    banner = s.recv(512).decode(errors="ignore").strip()
                    banner = " ".join(banner.split())[:120]
                    results.append(
                        f"  Port {port:5d}: {banner or '[connected, empty banner]'}"
                    )
                else:
                    results.append(f"  Port {port:5d}: [open]")
            s.close()
        except:
            pass
    return (
        ok("Banners:\n" + "\n".join(results))
        if results
        else wr("No banners grabbed (no open ports)")
    )


# ── [31] Common Port Scanner (Python) ────────────────────────────────────
def t31_port_scan(t):
    ip = t["ip"]
    if not ip:
        return err("No IP resolved")
    open_ports = []
    lock = threading.Lock()

    def probe(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            if s.connect_ex((ip, port)) == 0:
                with lock:
                    open_ports.append(port)
            s.close()
        except:
            pass

    threads = [
        threading.Thread(target=probe, args=(p,), daemon=True) for p in COMMON_PORTS
    ]
    for th in threads:
        th.start()
    for th in threads:
        th.join(timeout=6)

    if open_ports:
        return ok(
            f"Open ports on {ip} [{len(open_ports)}/{len(COMMON_PORTS)} checked]:\n"
            + ", ".join(str(p) for p in sorted(open_ports))
        )
    return wr(f"No common ports open on {ip}")


# ── [32] HTML Meta Tags & Title ──────────────────────────────────────────
def t32_meta_tags(t):
    try:
        r = http_get(t["url"])
        body = get_text(r)
        title_m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        title = title_m.group(1).strip()[:100] if title_m else "N/A"
        metas = re.findall(r"<meta[^>]+>", body, re.I)
        lines = [f"Title: {title}", "─" * 40, "Meta Tags:"]
        for meta in metas[:20]:
            name = re.search(r'(?:name|property)=["\']([^"\']+)["\']', meta, re.I)
            cont = re.search(r'content=["\']([^"\']{0,120})["\']', meta, re.I)
            if name and cont:
                lines.append(f"  {name.group(1):<30} {cont.group(1)}")
        generator_m = re.search(
            r'<meta[^>]+generator[^>]+content=["\']([^"\']+)', body, re.I
        )
        if generator_m:
            lines.append(f"\n  Generator: {generator_m.group(1)}")
        return ok("\n".join(lines))
    except Exception as ex:
        return err(str(ex))


# ── [33] Favicon Hash (Shodan Dork) ──────────────────────────────────────
def t33_favicon_hash(t):
    base = t["url"].rstrip("/")
    for fav_url in [base + "/favicon.ico", base + "/favicon.png"]:
        try:
            r = http_get(fav_url, timeout=8)
            if r.status_code == 200 and r.content:
                import base64

                md5_hash = hashlib.md5(r.content).hexdigest()
                # Calculate MurmurHash3 if mmh3 available
                try:
                    import mmh3

                    b64 = base64.encodebytes(r.content)
                    fhash = mmh3.hash(b64)
                    return ok(
                        f"Favicon: {fav_url}\n"
                        f"Size:    {len(r.content)} bytes\n"
                        f"MD5:     {md5_hash}\n"
                        f"Shodan hash (mmh3): {fhash}\n"
                        f"Shodan dork: http.favicon.hash:{fhash}"
                    )
                except ImportError:
                    return ok(
                        f"Favicon: {fav_url}\n"
                        f"Size:    {len(r.content)} bytes\n"
                        f"MD5:     {md5_hash}\n"
                        f"Note: install mmh3 for Shodan hash  (pip install mmh3)"
                    )
        except:
            pass
    return wr("No favicon found at common paths")


# ── [34] HackerTarget Subdomains ─────────────────────────────────────────
def t34_hackertarget_subs(t):
    if t["is_ip"]:
        return sk("N/A for IP")
    domain = t["domain"]
    try:
        r = http_get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=20)
        if r.status_code == 200:
            txt = r.text.strip()
            if "error" in txt.lower() or "API count" in txt:
                return wr(txt[:200])
            lines = txt.split("\n")
            subs = [l.split(",")[0] for l in lines if "," in l]
            return ok(
                f"HackerTarget subdomains ({len(subs)}):\n" + "\n".join(subs[:50])
            )
    except Exception as ex:
        return err(str(ex))
    return err("HackerTarget request failed")


# ── [35] Reverse IP Lookup ───────────────────────────────────────────────
def t35_reverse_ip(t):
    ip = t["ip"]
    if not ip:
        return err("No IP resolved")
    try:
        r = http_get(
            f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=20
        )
        if r.status_code == 200:
            txt = r.text.strip()
            if "error" in txt.lower():
                return wr(txt[:200])
            hosts = [h for h in txt.split("\n") if h.strip()]
            return ok(
                f"Reverse IP — {len(hosts)} domain(s) on {ip}:\n"
                + "\n".join(hosts[:40])
            )
    except Exception as ex:
        return err(str(ex))
    return err("Reverse IP lookup failed")


# ── [36] Technology Fingerprinting ───────────────────────────────────────
def t36_tech_detect(t):
    try:
        r = http_get(t["url"])
        body = get_text(r).lower()[:8000]
        h = {k.lower(): v.lower() for k, v in r.headers.items()}
        tech = []
        if "server" in h:
            tech.append(f"Server:       {h['server']}")
        if "x-powered-by" in h:
            tech.append(f"X-Powered-By: {h['x-powered-by']}")
        if "x-generator" in h:
            tech.append(f"X-Generator:  {h['x-generator']}")

        patterns = {
            "WordPress": ["wp-content", "wp-includes", "wordpress"],
            "Joomla": ["joomla", "/components/com_"],
            "Drupal": ["drupal", "sites/default/files"],
            "Laravel": ["laravel_session", "x-powered-by: php"],
            "Django": ["csrfmiddlewaretoken", "django"],
            "Ruby/Rails": ["x-powered-by: phusion", "x-runtime"],
            "React": ["__react", "react-dom", "_reactroot"],
            "Vue.js": ["__vue__", "vue.js"],
            "Angular": ["ng-version", "angular.js"],
            "jQuery": ["jquery"],
            "Bootstrap": ["bootstrap.css", "bootstrap.min"],
            "Cloudflare": ["cf-ray", "__cfduid", "cloudflare"],
            "AWS S3": ["x-amz-", "amazonaws"],
            "nginx": ["nginx"],
            "Apache": ["apache"],
            "IIS": ["x-aspnet-version", "x-powered-by: asp"],
            "PHP": ["x-powered-by: php"],
            "Node.js": ["x-powered-by: express"],
        }
        for name, kws in patterns.items():
            if any(kw in body or kw in str(h) for kw in kws):
                tech.append(f"Detected:     {name}")
        return ok("\n".join(tech) if tech else "No specific technologies fingerprinted")
    except Exception as ex:
        return err(str(ex))


# ══════════════════════════════════════════════════════════════════════════
#  ░░░░░░░░░░░░  KALI / ADVANCED TOOLS (37–50)  ░░░░░░░░░░░░
# ══════════════════════════════════════════════════════════════════════════


# ── [37] Nmap Quick Scan ─────────────────────────────────────────────────
def t37_nmap_quick(t):
    if not cmd_exists("nmap"):
        return sk("nmap not installed  (pkg install nmap  /  apt install nmap)")
    out, _, rc = run_cmd(
        ["nmap", "-T4", "--top-ports", "1000", "--open", "-oN", "-", t["host"]], 180
    )
    return (
        ok(out[:3500])
        if rc == 0 and out.strip()
        else err(out or "nmap returned no output")
    )


# ── [38] Nmap Service/Version Detection ──────────────────────────────────
def t38_nmap_service(t):
    if not cmd_exists("nmap"):
        return sk("nmap not installed")
    out, _, rc = run_cmd(["nmap", "-sV", "-T4", "--top-ports", "200", t["host"]], 240)
    return ok(out[:3500]) if rc == 0 else err(out)


# ── [39] Nmap OS Detection (Kali/root) ───────────────────────────────────
def t39_nmap_os(t):
    if not cmd_exists("nmap"):
        return sk("nmap not installed  [Kali: apt install nmap]")
    out, _, rc = run_cmd(["nmap", "-O", "-T4", "--top-ports", "100", t["host"]], 180)
    if "requires root" in (out + _).lower():
        return wr("OS detection requires root. Run: sudo python3 tool_definitive.py")
    return ok(out[:2500]) if rc == 0 else err(out)


# ── [40] Nmap Vuln Scripts ────────────────────────────────────────────────
def t40_nmap_vuln(t):
    if not cmd_exists("nmap"):
        return sk("nmap not installed  [Kali]")
    out, _, rc = run_cmd(
        ["nmap", "--script", "vuln", "-T3", "--top-ports", "100", t["host"]], 420
    )
    return ok(out[:5000]) if rc == 0 else err(out or _)


# ── [41] Masscan Full Port Range ──────────────────────────────────────────
def t41_masscan(t):
    if not cmd_exists("masscan"):
        return sk("masscan not installed  [Kali: apt install masscan]")
    ip = t["ip"]
    if not ip:
        return err("No IP resolved for masscan")
    out, _, rc = run_cmd(["masscan", "-p", "1-65535", "--rate", "500", ip], 600)
    return ok(out[:3000]) if rc == 0 else err(out or _)


# ── [42] Nikto Web Scanner ────────────────────────────────────────────────
def t42_nikto(t):
    if not cmd_exists("nikto"):
        return sk("nikto not installed  [Kali: apt install nikto]")
    out, _, rc = run_cmd(
        [
            "nikto",
            "-h",
            t["url"],
            "-maxtime",
            "90s",
            "-nointeractive",
            "-Format",
            "txt",
        ],
        180,
    )
    return ok(out[:5000]) if rc == 0 else err(out or _)


# ── [43] WhatWeb Fingerprinting ──────────────────────────────────────────
def t43_whatweb(t):
    if not cmd_exists("whatweb"):
        return sk("whatweb not installed  [Kali: apt install whatweb]")
    out, _, rc = run_cmd(["whatweb", "-a", "3", "--color", "never", t["url"]], 90)
    return ok(out[:3000]) if rc == 0 else err(out or _)


# ── [44] WafW00f WAF Detection ────────────────────────────────────────────
def t44_wafw00f(t):
    if not cmd_exists("wafw00f"):
        return sk(
            "wafw00f not installed  [pip install wafw00f  or  apt install wafw00f]"
        )
    out, _, rc = run_cmd(["wafw00f", t["url"]], 60)
    return ok(out[:2000]) if rc == 0 else err(out or _)


# ── [45] Subfinder Subdomain Enum ────────────────────────────────────────
def t45_subfinder(t):
    if t["is_ip"]:
        return sk("N/A for IP")
    if not cmd_exists("subfinder"):
        return sk("subfinder not installed  [go install / apt]")
    out, _, rc = run_cmd(
        ["subfinder", "-d", t["domain"], "-silent", "-timeout", "30"], 120
    )
    if out.strip():
        subs = out.strip().split("\n")
        return ok(f"Subfinder — {len(subs)} subdomains:\n{out[:3000]}")
    return wr("No subdomains found by subfinder")


# ── [46] Amass Passive Enum ───────────────────────────────────────────────
def t46_amass(t):
    if t["is_ip"]:
        return sk("N/A for IP")
    if not cmd_exists("amass"):
        return sk("amass not installed  [Kali: apt install amass]")
    out, _, rc = run_cmd(
        ["amass", "enum", "-passive", "-d", t["domain"], "-timeout", "4"], 300
    )
    if out.strip():
        subs = [l for l in out.strip().split("\n") if t["domain"] in l]
        return ok(f"Amass — {len(subs)} subdomains:\n" + "\n".join(subs[:60]))
    return wr("Amass returned no results")


# ── [47] theHarvester ─────────────────────────────────────────────────────
def t47_theharvester(t):
    if t["is_ip"]:
        return sk("N/A for IP")
    cmd_name = next(
        (c for c in ["theHarvester", "theharvester"] if cmd_exists(c)), None
    )
    if not cmd_name:
        return sk("theHarvester not installed  [Kali: apt install theharvester]")
    out, _, rc = run_cmd([cmd_name, "-d", t["domain"], "-b", "all", "-l", "100"], 180)
    return ok(out[:4000]) if rc == 0 else err(out or _)


# ── [48] dnsrecon ─────────────────────────────────────────────────────────
def t48_dnsrecon(t):
    if t["is_ip"]:
        return sk("N/A for IP")
    if not cmd_exists("dnsrecon"):
        return sk("dnsrecon not installed  [Kali: apt install dnsrecon]")
    out, _, rc = run_cmd(["dnsrecon", "-d", t["domain"], "-t", "std"], 180)
    return ok(out[:3500]) if rc == 0 else err(out or _)


# ── [49] dnsenum ─────────────────────────────────────────────────────────
def t49_dnsenum(t):
    if t["is_ip"]:
        return sk("N/A for IP")
    if not cmd_exists("dnsenum"):
        return sk("dnsenum not installed  [Kali: apt install dnsenum]")
    out, _, rc = run_cmd(
        ["dnsenum", "--nocolor", "--noreverse", "--threads", "5", t["domain"]], 240
    )
    return ok(out[:3500]) if rc == 0 else err(out or _)


# ── [50] Gobuster Directory Bruteforce ───────────────────────────────────
def t50_gobuster(t):
    if not cmd_exists("gobuster"):
        return sk("gobuster not installed  [Kali: apt install gobuster]")
    wordlists = [
        "/usr/share/wordlists/dirb/small.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    ]
    wl = next((w for w in wordlists if os.path.exists(w)), None)
    if not wl:
        return sk(
            "No wordlist found for gobuster. Install wordlists: apt install wordlists"
        )
    out, _, rc = run_cmd(
        [
            "gobuster",
            "dir",
            "-u",
            t["url"],
            "-w",
            wl,
            "-q",
            "-t",
            "20",
            "--timeout",
            "5s",
            "-x",
            "php,html,txt,asp,aspx",
        ],
        180,
    )
    return ok(out[:4000]) if rc == 0 else err(out or _)


def irdval(text):
    text = text.lower()

    negative_markers = [
        "nobody on reddit goes by that name",
        "sorry, nobody on reddit",
        "page not found",
        "suspended",
    ]


def extract_all_text(r):
    text = r.text.lower()

    # catch titles
    title_start = text.find("<title>")
    title_end = text.find("</title>")

    title = ""
    if title_start != -1 and title_end != -1:
        title = text[title_start:title_end]

    return text + " " + title
    return not any(m in text for m in negative_markers)


from bs4 import BeautifulSoup


def t51_username_search(t):
    username = t["input"]
    if not username:
        return err("No username provided")

    sites = {
        "GitHub": f"https://github.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}/",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "Instagram": f"https://www.instagram.com/{username}",
    }

    found = []

    for name, url in sites.items():
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            r = requests.get(url, headers=headers)
            if r.status_code == 404:
                continue

            if len(r.history) > 0 and "login" in r.url:
                continue
            soup = BeautifulSoup(sanitize(r.content), "html.parser")

            valid = True
            if name == "GitHub":
                if r.status_code == 404:
                    valid = False

            elif name == "Reddit":
                title = soup.title.text if soup.title else ""
                if "nobody on Reddit goes by that name" in title:
                    valid = False

            elif name == "Instagram":
                title = soup.title.text if soup.title else ""
                if "Page Not Found" in title:
                    valid = False

            elif name == "TikTok":
                if soup.find(string="Couldn't find this account"):
                    valid = False

            if valid:
                found.append(f"Found {name}: {url}")

        except Exception:
            continue

    return ok("\n".join(found)) if found else wr("No profiles found")


def t52_email_osint(t):
    email = t["input"]
    if "@" not in email:
        email = answertogmail(email)

    h = hashlib.md5(email.strip().lower().encode()).hexdigest()
    gravatar = f"https://www.gravatar.com/avatar/{h}"

    return ok(
        f"Email: {email}\n"
        f"Gravatar: {gravatar}\n"
        f"Check breaches manually: https://haveibeenpwned.com/account/{email}"
    )


def t53_google_dorks(t):
    domain = t["domain"]

    dorks = [
        f"site:{domain}",
        f"site:{domain} filetype:pdf",
        f"site:{domain} intitle:index of",
        f"site:{domain} inurl:admin",
        f"site:{domain} ext:log",
    ]

    return ok("Google dorks:\n" + "\n".join(dorks))


def t54_exif(t):
    path = input("Enter image path: ")

    try:
        import exifread

        with open(path, "rb") as f:
            tags = exifread.process_file(f)

        lines = [f"{k}: {v}" for k, v in list(tags.items())[:30]]
        return ok("\n".join(lines))
    except Exception as e:
        return err(str(e))


def t55_rblxuser(t):
    username = t["input"]
    if not username:
        return err("Nothing provided")

    try:
        r = requests.post(
            "https://users.roblox.com/v1/usernames/users",
            json={"usernames": [username], "excludeBannedUsers": False},
            timeout=30,
        )
        if r.status_code != 200:
            return wr(f"API error {r.status_code}")
        data = r.json()
        if not data.get("data"):
            return wr("User not found")

        user = data["data"][0]
        user_id = user["id"]
        username_real = user["name"]
        display_name = user["displayName"]
        created = "N/A"
        r2 = requests.get(f"https://users.roblox.com/v1/users/{user_id}", timeout=16)
        if r2.status_code == 200:
            created = r2.json().get("created", "N/A")
        friends = "N/A"
        followers = "N/A"

        rf = requests.get(
            f"https://friends.roblox.com/v1/users/{user_id}/friends/count", timeout=16
        )
        if rf.status_code == 200:
            friends = rf.json().get("count", "N/A")
        rfol = requests.get(
            f"https://friends.roblox.com/v1/users/{user_id}/followers/count", timeout=16
        )
        if rfol.status_code == 200:
            followers = rfol.json().get("count", "N/A")

        def gab(uid):
            url = f"https://badges.roblox.com/v1/users/{uid}/badges"
            count = 0
            cursor = None
            while True:
                params = {"limit": 100}
                if cursor:
                    params["cursor"] = cursor
                r = requests.get(url, params=params, timeout=16)
                if r.status_code != 200:
                    break
                data = r.json()
                count += len(data.get("data", []))
                cursor = data.get("nextPageCursor")
                if not cursor:
                    break
            return count

        badges = gab(user_id)
        return ok(f"""User: {username_real}
Display: {display_name}
User ID: {user_id}
Created: {created}
Friends: {friends}
Followers: {followers}
Badges: {badges}""")

    except Exception as ex:
        return err(str(ex))


def t56_SSID(t):
    ssid = t["input"]

    def wigle_ssid(t):
        api_key = "152532dbd8d49813474c5421642dd66e"
        headers = {"accept": "application/json", "Authorization": f"Basic {api_key}"}
        params = {"ssid": ssid}
        endpoint = "https://api.wigle.net/api/v2/network/search"
        try:
            response = requests.get(
                endpoint,
                headers=headers,
                params=params,
                # Disable SSL verification if specified in the configuration data
            )
            # If the request is successful
            if response.json()["success"]:
                # If the request is successful
                if response.json()["totalResults"] != 0:
                    # Get the results from the response
                    results = response.json()["results"]
                    # Create a list of dictionaries containing the data
                    data = [
                        {
                            "module": "wigle",
                            "bssid": result.get("netid", ""),
                            "ssid": result.get("ssid", ""),
                            "latitude": result.get("trilat", ""),
                            "longitude": result.get("trilong", ""),
                        }
                        for result in results
                    ]
                    return data
                else:
                    # Return an error message if the request is not successful
                    return {"module": "wigle", "error": "No results detected"}
            else:
                # Return an error message if the request is not successful
                return {"module": "wigle", "error": response.json()["message"]}
        except Exception as e:
            return err((e))

    clear()
    wigle_ssid


def t58_geoaddress(t):
    address = t["input"]
    formatted = {
        "raw": address,
        "street": None,
        "house_number": None,
        "city": None,
        "postal_code": None,
        "country": None,
        "lat": None,
        "lon": None,
    }
    address = " ".join(address.split())
    geo = geocode(address)
    if not geo:
        return err("cant find address")

    data = geo[0]
    addr = data.get("address", {})

    formatted["street"] = addr.get("road")
    formatted["house_number"] = addr.get("house_number")
    formatted["city"] = addr.get("city") or addr.get("town") or addr.get("village")
    formatted["postal_code"] = addr.get("postcode")
    formatted["country"] = addr.get("country")
    formatted["lat"] = data.get("lat")
    formatted["lon"] = data.get("lon")
    maplink = f"https://www.google.com/maps?q={formatted['lat']},{formatted['lon']}"
    mapearth = f"https://www.google.com/maps/@{formatted['lat']},{formatted['lon']},18z"
    earth = f"https://earth.google.com/web/@{formatted['lat']},{formatted['lon']},200a"
    return ok(
        f"Raw: {formatted['raw']}\n"
        f"Street: {formatted['street']}\n"
        f"House number: {formatted['house_number']}\n"
        f"City: {formatted['city']}\n"
        f"Postal code: {formatted['postal_code']}\n"
        f"Country: {formatted['country']}\n"
        f"Lat: {formatted.get('lat')}\n"
        f"Lon: {formatted.get('lon')}\n"
        f"Google map: {maplink}\n"
        f"Google map 1: {mapearth}\n"
        f"Google earth: {earth}\n"
    )


def answertogmail(email):
    if "@" not in email:
        return email + "@gmail.com"
    return email


# Tools
TOOLS = [
    # ── DNS ─────────────────────────────────────────────────────────────
    (1, "DNS A Records", "DNS", "both", t01_dns_a, "Resolve IPv4 A records"),
    (2, "DNS MX Records", "DNS", "both", t02_dns_mx, "Mail exchanger records"),
    (3, "DNS NS Records", "DNS", "both", t03_dns_ns, "Name server records"),
    (4, "DNS TXT Records", "DNS", "both", t04_dns_txt, "TXT (SPF/DKIM/DMARC)"),
    (5, "DNS AAAA (IPv6)", "DNS", "both", t05_dns_aaaa, "IPv6 AAAA records"),
    (6, "DNS CNAME", "DNS", "both", t06_dns_cname, "Canonical name records"),
    (
        7,
        "Reverse DNS (PTR)",
        "DNS",
        "both",
        t07_reverse_dns,
        "Reverse DNS / PTR lookup",
    ),
    (
        8,
        "Zone Transfer (AXFR)",
        "DNS",
        "both",
        t08_zone_transfer,
        "Attempt DNS zone transfer",
    ),
    # ── WHOIS ───────────────────────────────────────────────────────────
    (
        9,
        "WHOIS / RDAP",
        "WHOIS",
        "both",
        t09_whois_rdap,
        "Registration & ownership info",
    ),
    # ── IP Intelligence ─────────────────────────────────────────────────
    (10, "IP Geolocation", "IP Intel", "both", t10_ip_geoloc, "ip-api.com geolocation"),
    (11, "IPInfo.io", "IP Intel", "both", t11_ipinfo, "ipinfo.io full lookup"),
    (
        12,
        "Shodan InternetDB",
        "IP Intel",
        "both",
        t12_shodan_idb,
        "Shodan free (no API key)",
    ),
    (
        13,
        "BGP / ASN Info",
        "IP Intel",
        "both",
        t13_bgp_asn,
        "BGPView ASN & prefix data",
    ),
    (
        35,
        "Reverse IP Lookup",
        "IP Intel",
        "both",
        t35_reverse_ip,
        "Domains co-hosted on IP",
    ),
    # ── Reputation ──────────────────────────────────────────────────────
    (
        14,
        "GreyNoise Community",
        "Reputation",
        "both",
        t14_greynoise,
        "GreyNoise IP context",
    ),
    (15, "AbuseIPDB", "Reputation", "both", t15_abuseipdb, "Abuse reports & score"),
    (
        16,
        "ThreatCrowd",
        "Reputation",
        "both",
        t16_threatcrowd,
        "ThreatCrowd threat intel",
    ),
    (26, "VirusTotal", "Reputation", "both", t26_virustotal, "VirusTotal detections"),
    (27, "URLScan.io", "Reputation", "both", t27_urlscan, "URLScan.io scan history"),
    # ── Subdomain Enum ──────────────────────────────────────────────────
    (
        17,
        "crt.sh Cert Transparency",
        "Subdomains",
        "both",
        t17_crtsh,
        "Certificate transparency logs",
    ),
    (
        18,
        "DNSDumpster / HackerTgt",
        "Subdomains",
        "both",
        t18_dnsdumpster,
        "DNS enumeration via HT API",
    ),
    (
        34,
        "HackerTarget Subdomains",
        "Subdomains",
        "both",
        t34_hackertarget_subs,
        "HackerTarget subdomain API",
    ),
    (
        45,
        "Subfinder",
        "Subdomains",
        "kali",
        t45_subfinder,
        "Fast passive subdomain enum",
    ),
    (46, "Amass", "Subdomains", "kali", t46_amass, "Amass passive enum"),
    (
        47,
        "theHarvester",
        "Subdomains",
        "kali",
        t47_theharvester,
        "Email & subdomain harvester",
    ),
    # ── Web Analysis ────────────────────────────────────────────────────
    (19, "HTTP Headers", "Web", "both", t19_http_headers, "Full HTTP response headers"),
    (20, "SSL Certificate", "Web", "both", t20_ssl_cert, "SSL/TLS cert & cipher info"),
    (
        21,
        "Security Headers",
        "Web",
        "both",
        t21_security_headers,
        "HSTS/CSP/etc. audit",
    ),
    (22, "CORS Check", "Web", "both", t22_cors_check, "CORS misconfiguration probe"),
    (23, "robots.txt", "Web", "both", t23_robots_txt, "Fetch & parse robots.txt"),
    (24, "sitemap.xml", "Web", "both", t24_sitemap, "Find & parse sitemap"),
    (32, "HTML Meta Tags", "Web", "both", t32_meta_tags, "Page title & meta analysis"),
    (
        33,
        "Favicon Hash",
        "Web",
        "both",
        t33_favicon_hash,
        "Favicon hash for Shodan dork",
    ),
    (36, "Tech Detection", "Web", "both", t36_tech_detect, "CMS/framework fingerprint"),
    (43, "WhatWeb", "Web", "kali", t43_whatweb, "WhatWeb deep fingerprint"),
    (
        44,
        "WAF Detection (wafw00f)",
        "Web",
        "kali",
        t44_wafw00f,
        "Web Application Firewall detect",
    ),
    # ── Network ─────────────────────────────────────────────────────────
    (
        25,
        "Wayback Machine",
        "Network",
        "both",
        t25_wayback,
        "Internet Archive snapshots",
    ),
    (28, "Ping", "Network", "both", t28_ping, "ICMP echo test"),
    (29, "Traceroute", "Network", "both", t29_traceroute, "Network path tracing"),
    (30, "Banner Grabbing", "Network", "both", t30_banner_grab, "TCP service banners"),
    (
        31,
        "Port Scanner (Python)",
        "Network",
        "both",
        t31_port_scan,
        "Common ports quick scan",
    ),
    # ── Port Scanning (nmap/masscan) ────────────────────────────────────
    (37, "Nmap Quick Scan", "Port Scan", "both", t37_nmap_quick, "nmap top 1000 ports"),
    (
        38,
        "Nmap Service Versions",
        "Port Scan",
        "both",
        t38_nmap_service,
        "nmap -sV service detect",
    ),
    (
        39,
        "Nmap OS Detection",
        "Port Scan",
        "kali",
        t39_nmap_os,
        "nmap -O OS fingerprint",
    ),
    (40, "Nmap Vuln Scripts", "Port Scan", "kali", t40_nmap_vuln, "nmap --script vuln"),
    (
        41,
        "Masscan Full Range",
        "Port Scan",
        "kali",
        t41_masscan,
        "masscan all 65535 ports",
    ),
    # ── Web Vulnerabilities ─────────────────────────────────────────────
    (42, "Nikto Web Scan", "Web Vuln", "kali", t42_nikto, "Nikto web vuln scanner"),
    (
        50,
        "Gobuster Dirs",
        "Web Vuln",
        "kali",
        t50_gobuster,
        "Directory/file bruteforce",
    ),
    # ── DNS Recon (Kali) ────────────────────────────────────────────────
    (48, "dnsrecon", "DNS Recon", "kali", t48_dnsrecon, "dnsrecon standard enum"),
    (49, "dnsenum", "DNS Recon", "kali", t49_dnsenum, "dnsenum full enumeration"),
    # ──Public sources─────────────────────────────────────────────────────
    (
        51,
        "Username Search",
        "OSINT",
        "both",
        t51_username_search,
        "Find username across platforms",
    ),
    # ── OSINT Extended ─────────────────────────────────────────────
    (52, "Email OSINT", "OSINT", "both", t52_email_osint, "Gravatar + breach check"),
    (
        53,
        "Google Dorks",
        "OSINT",
        "both",
        t53_google_dorks,
        "Generate Google dorks for domain",
    ),
    (54, "EXIF Metadata", "OSINT", "both", t54_exif, "Extract image metadata (EXIF)"),
    # ── Roblox platform osint ─────────────────────────────────────────────
    (
        55,
        "Get roblox usernames",
        "OSINT",
        "both",
        t55_rblxuser,
        "Pull usernames from roblox (not always right tho)",
    ),
    # ── Wifi OSINT ─────────────────────────────────────────────
    (56, "SSID finder", "OSINT", "both", t56_SSID, "Search SSID"),
    # ── Geo OSINT ─────────────────────────────────────────────
    (58, "Address finder", "OSINT", "both", t58_geoaddress, "Search SSID"),
]
OSINT_PRESETS = {
    "1": [51],  # Person → Username search , 52 ,25 adding 8ter
    "2": [1, 2, 3, 4, 6, 9, 19, 20, 36, 25, 53, 26, 23, 18],  # Website, (18,17)
    "3": [7, 10, 11, 12, 13, 14, 15, 35],  # IP
    "4": [55, 52],  # Username, 52 can add @xxx.com
    "5": [27, 53, 55],  # Keyword (Wayback + URLScan), 25 cant add
    "6": [56],  # ignore ts
    "7": [57],  # ignore ts too
    "8": [58],  # find address (done)
}
