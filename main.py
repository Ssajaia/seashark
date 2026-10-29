"""SeaShark - find insecure (plaintext) traffic in .pcap/.pcapng files."""
import argparse
import base64
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import parse_qs

from scapy.all import DNS, ICMP, IP, IPv6, PcapReader, Raw, TCP, UDP
from scapy.error import Scapy_Exception
from scapy.layers.snmp import SNMP

HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE")
HTTP_START = tuple(m.encode() + b" " for m in HTTP_METHODS) + (b"HTTP/1.",)
PLAIN_PORTS = {80: "HTTP", 8080: "HTTP", 8000: "HTTP", 21: "FTP", 23: "Telnet",
               25: "SMTP", 587: "SMTP", 110: "POP3", 143: "IMAP"}
SECURE_PORTS = {443: "HTTPS", 8443: "HTTPS", 22: "SSH", 993: "IMAPS", 995: "POP3S",
                465: "SMTPS", 636: "LDAPS", 853: "DNS-over-TLS"}
TLS_TYPES = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "ApplicationData"}
FLAGS = {"F": "FIN", "S": "SYN", "R": "RST", "P": "PSH", "A": "ACK", "U": "URG", "E": "ECE", "C": "CWR"}
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV"}
DNS_RCODES = {1: "FormErr", 2: "ServFail", 3: "NXDomain", 4: "NotImp", 5: "Refused"}
CRED_KEY = re.compile(r"pass|pwd|user|login|email|token", re.I)
MAX_PAYLOAD = 2000


def clean(data):
    """Bytes -> printable ASCII text ('.' for anything else, CR removed)."""
    if not isinstance(data, bytes):
        return str(data)
    return "".join(chr(b) if 32 <= b < 127 or b in (9, 10) else "." for b in data if b != 13)


def as_list(x):
    return x if isinstance(x, list) else ([x] if x else [])


def identify(data, ports):
    """Guess the protocol of a TCP payload. Returns (name, is_secure)."""
    if len(data) >= 5 and data[0] in TLS_TYPES and data[1] == 3 and data[2] <= 4:
        return "TLS", True
    if data.startswith(b"SSH-"):
        return "SSH", True
    if data.startswith(HTTP_START):
        return "HTTP", False
    for p in ports:
        if p in PLAIN_PORTS:
            return PLAIN_PORTS[p], False
    for p in ports:
        if p in SECURE_PORTS:
            return SECURE_PORTS[p], True
    return None, False


def parse_http(data, r):
    head, _, body = data.partition(b"\r\n\r\n")
    lines = clean(head).split("\n")
    req = re.match(r"([A-Z]+) (\S+) HTTP/\d", lines[0])
    resp = re.match(r"HTTP/\d\.\d (\d{3})", lines[0])
    if not (req or resp):  # e.g. a continuation segment
        r["payload"] = clean(data)
        return
    r["summary"] = lines[0]
    r["headers"] = [tuple(x.strip() for x in l.split(":", 1)) for l in lines[1:] if ":" in l]
    r["payload"] = clean(body)
    if resp:
        r["method"] = "RESPONSE"
        if int(resp.group(1)) >= 400:
            r["failed"] = "HTTP " + resp.group(1)
        return
    r["method"] = req.group(1)
    h = {k.lower(): v for k, v in r["headers"]}
    auth = h.get("authorization") or h.get("proxy-authorization")
    if auth:
        scheme, _, value = auth.partition(" ")
        try:
            if scheme.lower() != "basic":
                raise ValueError
            r["creds"].append("Basic auth: " + clean(base64.b64decode(value)))
        except ValueError:
            r["creds"].append("Authorization header: " + auth)
    if r["method"] in ("POST", "PUT", "PATCH") and body:
        text = clean(body)
        pairs = [(k, v[0]) for k, v in parse_qs(text).items()]  # form data
        pairs += re.findall(r'"([^"]*)"\s*:\s*"([^"]*)"', text)  # simple JSON
        r["creds"] += [f"{k}: {v}" for k, v in pairs if CRED_KEY.search(k)]


def parse_lines(proto, data, r):
    """FTP, POP3, SMTP and IMAP are line-based; only the first line is inspected."""
    text = clean(data).strip()
    r["payload"] = text
    first = text.split("\n")[0].strip()
    words = first.split()
    if not words:
        return
    r["summary"] = first
    word = words[0].upper()
    rest = first[len(words[0]):].strip()

    if proto == "POP3" and first[:1] in "+-":
        r["method"] = "RESPONSE"
        if first.startswith("-ERR"):
            r["failed"] = "POP3 -ERR"
        return
    if proto in ("FTP", "SMTP") and re.match(r"\d{3}", first):
        r["method"] = "RESPONSE"
        if int(first[:3]) >= 400:
            r["failed"] = f"{proto} {first[:3]}"
        return
    if proto == "IMAP":
        if word == "*":
            r["method"] = "RESPONSE"
        elif len(words) > 1 and words[1].upper() in ("OK", "NO", "BAD"):
            r["method"] = "RESPONSE"
            if words[1].upper() != "OK":
                r["failed"] = "IMAP " + words[1].upper()
        elif len(words) > 1:
            r["method"] = words[1].upper()
            if r["method"] == "LOGIN" and len(words) >= 4:
                r["creds"].append(f"username: {words[2].strip(chr(34))}")
                r["creds"].append(f"password: {words[3].strip(chr(34))}")
        return

    r["method"] = word
    if proto in ("FTP", "POP3") and word == "USER":
        r["creds"].append("username: " + rest)
    elif proto in ("FTP", "POP3") and word == "PASS":
        r["creds"].append("password: " + rest)
    elif proto in ("SMTP", "POP3") and word == "AUTH":
        parts = rest.split()
        if len(parts) == 2 and parts[0].upper() == "PLAIN":
            try:
                _, user, pw = base64.b64decode(parts[1]).split(b"\0")
                r["creds"] += ["username: " + clean(user), "password: " + clean(pw)]
            except ValueError:
                pass


def parse_telnet(data, r):
    data = re.sub(rb"\xff\xfa.*?\xff\xf0|\xff[\xfb-\xfe].|\xff.", b"", data, flags=re.S)
    r["payload"] = clean(data) or "(telnet option negotiation only)"


def parse_dns(pkt, r):
    dns = pkt[DNS]
    r["protocol"] = "DNS"
    q = as_list(dns.qd)
    qtype = DNS_TYPES.get(q[0].qtype, q[0].qtype) if q else None
    name = clean(q[0].qname) if q else None
    r["summary"] = f"{qtype} {name}" if q else None
    if dns.qr == 0:
        r["method"] = "QUERY"
        return
    r["method"] = "RESPONSE"
    answers = as_list(dns.an)[:dns.ancount]
    r["payload"] = "\n".join(
        f"{clean(a.rrname)} {DNS_TYPES.get(a.type, a.type)} {clean(a.rdata)}" for a in answers)
    if dns.rcode != 0:
        r["failed"] = f"DNS rcode {dns.rcode} ({DNS_RCODES.get(dns.rcode, 'other')})"


def parse_snmp(pkt, r):
    snmp = pkt[SNMP]
    r["protocol"] = "SNMP"
    r["method"] = type(snmp.PDU).__name__
    community = getattr(snmp.community, "val", None)
    if community is not None:
        r["creds"].append("SNMP community string: " + clean(community))
    err = getattr(getattr(snmp.PDU, "error", None), "val", 0)
    if err:
        r["failed"] = f"SNMP error-status {err}"
    r["payload"] = "\n".join(
        f"{v.oid.val} = {getattr(v.value, 'val', '')}" for v in getattr(snmp.PDU, "varbindlist", []))


def analyze(pkt):
    """Turn one packet into a record dict, or None if nothing identifiable."""
    if pkt.haslayer(ICMP):
        return None
    if pkt.haslayer(IP):
        ip, ttl = pkt[IP], pkt[IP].ttl
    elif pkt.haslayer(IPv6):
        ip, ttl = pkt[IPv6], pkt[IPv6].hlim
    else:
        return None
    if pkt.haslayer(TCP):
        l4, transport = pkt[TCP], "TCP"
    elif pkt.haslayer(UDP):
        l4, transport = pkt[UDP], "UDP"
    else:
        return None

    data = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
    r = {"time": float(pkt.time), "src": ip.src, "dst": ip.dst, "sport": l4.sport,
         "dport": l4.dport, "transport": transport, "ttl": ttl, "flags": None,
         "seq": None, "ack": None, "length": len(data), "protocol": None,
         "method": None, "secure": False, "summary": None, "failed": None,
         "headers": [], "creds": [], "payload": ""}

    if transport == "UDP":
        if l4.len:
            r["length"] = l4.len - 8
        if pkt.haslayer(DNS):
            parse_dns(pkt, r)
        elif pkt.haslayer(SNMP):
            parse_snmp(pkt, r)
        else:
            return None
        return r

    flags = str(l4.flags)
    names = ", ".join(FLAGS[c] for c in flags if c in FLAGS)
    r["flags"] = f"{flags} ({names})" if flags else "none"
    r["seq"], r["ack"] = l4.seq, l4.ack
    if not data:
        return None
    proto, secure = identify(data, (l4.dport, l4.sport))
    if not proto:
        return None
    r["protocol"], r["secure"] = proto, secure
    if secure:
        if proto == "TLS":
            r["summary"] = f"TLS record: {TLS_TYPES[data[0]]}, record version 0x{data[1]:02x}{data[2]:02x}"
        elif proto == "SSH" and data.startswith(b"SSH-"):
            r["summary"] = clean(data).strip().split("\n")[0]
        r["payload"] = None
    elif proto == "HTTP":
        parse_http(data, r)
    elif proto == "Telnet":
        parse_telnet(data, r)
    else:
        parse_lines(proto, data, r)
    return r


def matches(r, args):
    if r["secure"] and not args.safe:
        return False
    if args.i and args.i not in (r["src"], r["dst"]):
        return False
    if args.p is not None and args.p not in (r["sport"], r["dport"]):
        return False
    if args.m and (r["method"] or "").upper() != args.m.upper():
        return False
    return True


def fmt(r):
    when = datetime.fromtimestamp(r["time"], timezone.utc).isoformat()
    tag = " (secure)" if r["secure"] else ""
    out = [f"[#{r['num']}] {when}",
           f"  {r['protocol']}{tag}  {r['src']}:{r['sport']} -> {r['dst']}:{r['dport']}  [{r['transport']}]"]
    details = [("TTL", r["ttl"]), ("TCP flags", r["flags"]), ("Seq", r["seq"]), ("Ack", r["ack"]),
               ("Payload length", f"{r['length']} bytes" if r["length"] is not None else None),
               ("Method", r["method"]), ("Summary", r["summary"])]
    out += [f"  {k}: {v}" for k, v in details if v is not None]
    if r["failed"]:
        out.append(f"  FAILED: {r['failed']}")
    if r["creds"]:
        out.append("  Credentials:")
        out += [f"    - {c}" for c in r["creds"]]
    if r["headers"]:
        out.append("  Headers:")
        out += [f"    {k}: {v}" for k, v in r["headers"]]
    if r["secure"]:
        out.append("  Payload: not shown (secure protocol)")
    elif r["payload"] and r["payload"].strip():
        p = r["payload"].strip("\n")
        if len(p) > MAX_PAYLOAD:
            p = p[:MAX_PAYLOAD] + f"\n... [{len(p) - MAX_PAYLOAD} more characters truncated]"
        out.append("  Payload:")
        out += ["    " + line for line in p.split("\n")]
    return "\n".join(out) + "\n"


def summarize(records, total, name):
    def table(title, counter, limit=None):
        lines = [f"\n{title}:"]
        lines += [f"  {k}: {v}" for k, v in counter.most_common(limit)] or ["  (none)"]
        return lines

    secure = sum(r["secure"] for r in records)
    out = [f"SeaShark summary for {name}",
           f"Packets read: {total}",
           f"Matching packets: {len(records)} (insecure: {len(records) - secure}, secure: {secure})",
           f"Failed requests/responses: {sum(1 for r in records if r['failed'])}",
           f"Credentials found: {sum(len(r['creds']) for r in records)}"]
    out += table("Protocols", Counter(r["protocol"] for r in records))
    out += table("Methods", Counter(r["method"] for r in records if r["method"]))
    out += table("Failures", Counter(r["failed"] for r in records if r["failed"]))
    out += table("Top conversations",
                 Counter(f"{r['src']}:{r['sport']} -> {r['dst']}:{r['dport']}" for r in records), 10)
    creds = [f"#{r['num']} {r['protocol']} {r['src']} -> {r['dst']}: {c}" for r in records for c in r["creds"]]
    out += ["\nCredentials:"] + [f"  {c}" for c in creds] if creds else ["\nCredentials:", "  (none)"]
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser(description="SeaShark: find insecure traffic in pcap/pcapng files.")
    ap.add_argument("pcap", help="capture file (.pcap or .pcapng)")
    ap.add_argument("-f", metavar="FILE", help="save output to FILE")
    ap.add_argument("-i", metavar="IP", help="filter by source or destination IP")
    ap.add_argument("-m", metavar="METHOD", help="filter by method (case-insensitive)")
    ap.add_argument("-p", metavar="PORT", type=int, help="filter by source or destination port")
    ap.add_argument("--safe", action="store_true", help="also include secure/encrypted traffic")
    ap.add_argument("--count", action="store_true", help="show counts and summaries only")
    args = ap.parse_args()

    try:
        reader = PcapReader(args.pcap)
    except (OSError, Scapy_Exception) as e:
        sys.exit(f"Error: cannot read '{args.pcap}': {e}")

    records, total = [], 0
    try:
        for pkt in reader:
            total += 1
            try:
                r = analyze(pkt)
            except Exception:  # skip malformed packets
                continue
            if r:
                r["num"] = total
                if matches(r, args):
                    records.append(r)
    except Exception as e:
        print(f"Warning: stopped reading after packet {total}: {e}", file=sys.stderr)
    finally:
        reader.close()

    if args.count:
        text = summarize(records, total, args.pcap)
    elif records:
        text = "\n".join(fmt(r) for r in records)
        text += f"\nPackets read: {total}, shown: {len(records)}\n"
    else:
        text = f"No matching traffic found ({total} packets read).\n"

    if args.f:
        try:
            with open(args.f, "w", encoding="utf-8") as out:
                out.write(text)
        except OSError as e:
            sys.exit(f"Error: cannot write '{args.f}': {e}")
        print(f"Output saved to {args.f}")
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
