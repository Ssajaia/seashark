# SeaShark

A small Python CLI that uses Scapy to find insecure (plaintext) traffic in `.pcap` / `.pcapng` files, including plaintext credentials and failed requests.

## Install

```
pip install -r requirements.txt
```

## Usage

```
py main.py capture.pcap [-f FILE] [-i IP] [-m METHOD] [-p PORT] [--safe] [--count]
```

| Option | Description |
|---|---|
| `-f FILE` | Save output to a file instead of printing it |
| `-i IP` | Keep packets where the source or destination IP matches |
| `-m METHOD` | Keep packets with this method (case-insensitive) |
| `-p PORT` | Keep packets where the source or destination port matches |
| `--safe` | Also include secure/encrypted traffic (TLS, SSH, HTTPS, ...) |
| `--count` | Show counts and summaries instead of packet details |

All filters can be combined:

```
py main.py capture.pcap -f out.txt -i 192.168.20.5 -m POST -p 80 --count
```

## What it detects

- **HTTP**: request line, headers, body, Basic auth, `Authorization` headers, login form/JSON fields, 4xx/5xx responses
- **FTP, POP3, SMTP, IMAP**: commands and replies, `USER`/`PASS`, `LOGIN`, `AUTH PLAIN`, error replies
- **Telnet**: raw data (option negotiation removed)
- **DNS** (UDP): queries, answers, error codes
- **SNMP** (UDP): community strings, PDU type, errors

Secure traffic (only shown with `--safe`) is metadata only: payloads are not decoded.

## Notes

- `-m` matches HTTP verbs, protocol commands (`USER`, `LOGIN`, ...), `QUERY`/`RESPONSE` for DNS, SNMP PDU names, and `RESPONSE` for server replies. Secure traffic has no method, so it is excluded when `-m` is used.
- Only fields present in the capture are shown; nothing is guessed.
- Packets without payload (e.g. bare SYN/ACK) are skipped. Telnet and SMTP `AUTH LOGIN` logins sent across several packets are shown as-is, not reassembled.
- Output is plain ASCII; non-printable bytes appear as `.`, and payloads over 2000 characters are truncated.
