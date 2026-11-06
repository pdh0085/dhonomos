#!/usr/bin/env bash
# Daily security report for a Dhonomos host with listeners on the internet.
# Time window -> what was refused + what was let in, from 4 sources -> one text report.
# Changes nothing, needs no root. Reads only: Dhonomos log files,
# Apache access logs (if readable), kernel log via journalctl (if this
# user may read it, e.g. member of the adm or systemd-journal group).
#
# Usage:
#   scripts/security-report.sh [--since TIME] [--until TIME] [--out FILE]
#                              [--log-dir DIR] [--apache-dir DIR] [--wan-if IF]
#                              [--known-ips LIST] [--lab-nets LIST]
#     --since TIME      Window start; anything 'date -d' reads, e.g. '24 hours ago',
#                       '2026-10-15 09:00', 'yesterday' (default: 24 hours ago)
#     --until TIME      Window end (default: now)
#     --out FILE        Report -> FILE instead of stdout (creates its directory)
#     --log-dir DIR     Directory of the server's dhonomos*.log
#                       (default: ~/.local/state/dhonomos-dev)
#     --apache-dir DIR  Apache logs: *access*.log*, also rotated + .gz ones
#                       (default: /var/log/apache2; skipped if not readable)
#     --wan-if IF       Internet-facing interface in the firewall log (default: none -> all)
#     --known-ips LIST  Comma-separated addresses or CIDRs of devices expected to
#                       reach the listeners (default: none); auth failures
#                       from any other address -> attention list (none set -> all)
#     --lab-nets LIST   Comma-separated addresses or CIDRs of the lab, left out of the web
#                       section (default: 127.0.0.0/8,::1/128 = loopback only)
#     --journal-file F  Firewall lines from F (journalctl -o short-unix output), no
#                       journalctl call; for tests + replays
#
# Counted refusal lines: written by the server at info level, e.g.
#   request refused listener=cwmp remote=203.0.113.9:51514 reason=auth_failed username="admin"
# Per (listener, reason, source address): max 1 log line / 10 min, + 'suppressed=N'
# for the left-out repeats -> counts here include those repeats.
#
# Cron example (not installed by this script):
#   0 9 * * * /opt/dhonomos/scripts/security-report.sh --out "$HOME/.local/state/dhonomos-dev/security/$(date +\%F).txt"
#
# Exit status: 0 report written, 1 report could not be written,
# 64 bad arguments or missing tool.
set -uo pipefail
umask 077

since="24 hours ago"
until_time="now"
out=""
log_dir="$HOME/.local/state/dhonomos-dev"
apache_dir="/var/log/apache2"
wan_if=""  # empty -> no IN= filter, firewall lines of every interface
known_ips=""  # empty -> every device auth failure in the attention list
lab_nets="127.0.0.0/8,::1/128"
journal_file=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --since) since="${2:?}"; shift 2 ;;
    --until) until_time="${2:?}"; shift 2 ;;
    --out) out="${2:?}"; shift 2 ;;
    --log-dir) log_dir="${2:?}"; shift 2 ;;
    --apache-dir) apache_dir="${2:?}"; shift 2 ;;
    --wan-if) wan_if="${2:?}"; shift 2 ;;
    --known-ips) known_ips="${2:?}"; shift 2 ;;
    --lab-nets) lab_nets="${2:?}"; shift 2 ;;
    --journal-file) journal_file="${2:?}"; shift 2 ;;
    -h|--help) sed -n '2,38p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done

need() { command -v "$1" >/dev/null 2>&1; }
for tool in python3 date; do
  need "$tool" || { echo "missing tool: $tool" >&2; exit 64; }
done
since_epoch="$(date -d "$since" +%s 2>/dev/null)" || { echo "cannot read --since '$since' (see 'man date')" >&2; exit 64; }
until_epoch="$(date -d "$until_time" +%s 2>/dev/null)" || { echo "cannot read --until '$until_time'" >&2; exit 64; }
if [[ "$since_epoch" -ge "$until_epoch" ]]; then
  echo "--since must be before --until" >&2; exit 64
fi

tmp="$(mktemp -d)" || exit 1
trap 'rm -rf "$tmp"' EXIT

# Firewall: UFW BLOCK lines on the internet-facing interface (empty --wan-if -> all).
# Pre-filter in bash: kernel log can be large -> report program reads only the rest.
ufw_file="$tmp/ufw.txt"
ufw_note=""
: >"$ufw_file"
# stdin -> lines of $wan_if only; empty wan_if -> all lines pass.
wan_filter() {
  if [[ -n "$wan_if" ]]; then grep -F "IN=$wan_if "; else cat; fi
}
if [[ -n "$journal_file" ]]; then
  if [[ -r "$journal_file" ]]; then
    grep -F 'UFW BLOCK' "$journal_file" | wan_filter >"$ufw_file"
    ufw_note="read from $journal_file"
  else
    ufw_note="skipped: cannot read $journal_file"
  fi
elif ! need journalctl; then
  ufw_note="skipped: journalctl is not installed"
else
  since_local="$(date -d "@$since_epoch" '+%Y-%m-%d %H:%M:%S')"
  until_local="$(date -d "@$until_epoch" '+%Y-%m-%d %H:%M:%S')"
  if [[ -n "$(journalctl -k -q --no-pager -n 1 -o cat 2>/dev/null)" ]]; then
    journalctl -k -q --no-pager -o short-unix --since "$since_local" --until "$until_local" 2>/dev/null \
      | grep -F 'UFW BLOCK' | wan_filter >"$ufw_file"
    if [[ -s "$ufw_file" ]]; then
      ufw_note="journalctl -k"
    else
      ufw_note="journalctl -k (no UFW BLOCK line on ${wan_if:-any interface} in the window)"
    fi
  else
    ufw_note="skipped: journalctl -k shows nothing to this user (join the adm or systemd-journal group, or read the journal as root)"
  fi
fi

if [[ -n "$out" ]]; then
  mkdir -p "$(dirname "$out")" || { echo "cannot create the directory of $out" >&2; exit 1; }
  exec >"$out" || { echo "cannot write $out" >&2; exit 1; }
fi

python3 -I - "$since_epoch" "$until_epoch" "$log_dir" "$apache_dir" "$wan_if" "$known_ips" \
    "$lab_nets" "$ufw_file" "$ufw_note" "$(hostname)" <<'PY'
import collections
import datetime
import gzip
import ipaddress
import os
import re
import sys

(since_s, until_s, LOG_DIR, APACHE_DIR, WAN_IF, KNOWN_SPEC, LAB_SPEC, UFW_FILE, UFW_NOTE,
 HOST) = sys.argv[1:11]
SINCE, UNTIL = int(since_s), int(until_s)
TOP = 20
MAX_LINES = 30  # listed items per section where a list can be long

# ---------------------------------------------------------------- helpers
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
CTRL = re.compile(r"[\x00-\x1f\x7f]")


def clean(text, limit=120):
    """Text from a log made safe to print: no control characters, bounded length."""
    text = CTRL.sub("?", text)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def nets(spec):
    out = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            out.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            print(f"warning: ignoring unusable address list entry {part!r}", file=sys.stderr)
    return out


KNOWN, LAB = nets(KNOWN_SPEC), nets(LAB_SPEC)


def as_ip(text):
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def norm_ip(text):
    ip = as_ip(text)
    return str(ip) if ip else text


def within(text, where):
    ip = as_ip(text)
    return bool(ip) and any(ip.version == n.version and ip in n for n in where)


def split_remote(value):
    """'1.2.3.4:5', '[::1]:5', '::1' or 'unknown' -> (address, port or '')."""
    if value.startswith("["):
        ip, _, rest = value[1:].partition("]")
        return norm_ip(ip), rest.lstrip(":")
    if value.count(":") == 1:
        ip, port = value.split(":")
        return norm_ip(ip), port
    return norm_ip(value), ""


def stamp(epoch):
    return datetime.datetime.fromtimestamp(epoch).astimezone().strftime("%Y-%m-%d %H:%M:%S")


def window_text():
    return f"{stamp(SINCE)} to {stamp(UNTIL)} ({datetime.datetime.fromtimestamp(SINCE).astimezone().strftime('%z')})"


def readable(path):
    return os.access(path, os.R_OK)


def fresh(path):
    """Whether the file was written in or after the window (older files hold only older lines)."""
    try:
        return os.stat(path).st_mtime >= SINCE
    except OSError:
        return False


def open_text(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "rt", encoding="utf-8", errors="replace")


def table(rows, headers, indent="  "):
    rows = [[str(c) for c in r] for r in rows]
    widths = [len(h) for h in headers]
    for r in rows:
        for i, c in enumerate(r):
            widths[i] = max(widths[i], len(c))
    lines = [indent + "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)).rstrip()]
    for r in rows:
        lines.append(indent + "  ".join(c.ljust(widths[i]) for i, c in enumerate(r)).rstrip())
    return lines


def skipped_text(skipped):
    """'; skipped: ...' for the list of files not read; long lists are counted, not listed."""
    if not skipped:
        return ""
    if len(skipped) > 4:
        old = sum(1 for s in skipped if s.endswith("(older than the window)"))
        other = [s for s in skipped if not s.endswith("(older than the window)")]
        parts = ([f"{old} older than the window"] if old else []) + other
        return "; skipped: " + ", ".join(parts)
    return "; skipped: " + ", ".join(skipped)


def top(counter, n=TOP):
    return counter.most_common(n)


def first_last(times):
    return (stamp(min(times)), stamp(max(times))) if times else ("-", "-")


def label(ip):
    if within(ip, KNOWN):
        return f"{ip} (known device)"
    if within(ip, LAB):
        return f"{ip} (lab)"
    return ip


# ---------------------------------------------------------------- Dhonomos logs
ISO = re.compile(r"^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d+))?Z\s")
REFUSED = re.compile(
    r"(?:connection|request) refused listener=(\S+) remote=(\S+) reason=(\S+)(?: suppressed=(\d+))?(.*)$"
)
SUPPRESSED = re.compile(
    r"refusals suppressed listener=(\S+) remote=(\S+) reason=(\S+) suppressed=(\d+)"
)
USERNAME = re.compile(r'username="((?:[^"\\]|\\.)*)"')
AGENT = re.compile(r'agent="?([^"\s]+)"?')
REMOTE_KV = re.compile(r"\bremote=(\S+)")
XMPP_LOGIN = re.compile(r"XMPP login accepted account=(\S+) remote=(\S+)")
USP_CONNECTED = re.compile(r"USP (WebSocket|STOMP|MQTT) connected(.*)$")
OWN_CRED = re.compile(r"(per-device credentials active|CPE uses its own ACS credential)")
API_FAILED = re.compile(r"failed login username=(\S*) client=(\S+)")
SSO_FAILED = re.compile(r"single sign-on failed")
CROSS_ORIGIN = re.compile(r"cross-origin change request refused")
BLOCKING = re.compile(r"blocking a source after repeated")


def epoch_of(m):
    y, mo, d, h, mi, s = (int(m.group(i)) for i in range(1, 7))
    dt = datetime.datetime(y, mo, d, h, mi, s, tzinfo=datetime.timezone.utc)
    return int(dt.timestamp())


refusals = []  # dicts: t, listener, ip, reason, count, username
flushes = 0
xmpp_logins = []  # (t, account, ip)
usp_connects = []  # (t, kind, agent, ip)
own_cred = []  # (t, text, device)
api_failed = []  # (t, username, ip)
other_notes = collections.Counter()
log_files, log_skipped, log_lines_in_window = [], [], 0

if os.path.isdir(LOG_DIR):
    for name in sorted(os.listdir(LOG_DIR)):
        path = os.path.join(LOG_DIR, name)
        if not (name.startswith("dhonomos") and name.endswith(".log")):
            continue
        if not readable(path):
            log_skipped.append(f"{name} (not readable)")
            continue
        if not fresh(path):
            log_skipped.append(f"{name} (older than the window)")
            continue
        log_files.append(name)
        with open_text(path) as fh:
            for raw in fh:
                line = ANSI.sub("", raw.rstrip("\n"))
                m = ISO.match(line)
                if not m:
                    continue
                t = epoch_of(m)
                if not SINCE <= t < UNTIL:
                    continue
                log_lines_in_window += 1
                body = line[m.end():]
                r = REFUSED.search(body)
                if r:
                    listener, remote, reason, repeats, rest = r.groups()
                    u = USERNAME.search(rest)
                    ip, _ = split_remote(remote)
                    refusals.append({
                        "t": t, "listener": listener, "ip": ip, "reason": reason,
                        "count": 1 + int(repeats or 0),
                        "username": u.group(1) if u else None,
                    })
                    continue
                r = SUPPRESSED.search(body)
                if r:
                    listener, remote, reason, repeats = r.groups()
                    ip, _ = split_remote(remote)
                    refusals.append({
                        "t": t, "listener": listener, "ip": ip, "reason": reason,
                        "count": int(repeats), "username": None, "flush": True,
                    })
                    flushes += 1
                    continue
                r = XMPP_LOGIN.search(body)
                if r:
                    xmpp_logins.append((t, r.group(1), split_remote(r.group(2))[0]))
                    continue
                r = USP_CONNECTED.search(body)
                if r:
                    a = AGENT.search(body)
                    rem = REMOTE_KV.search(r.group(2))
                    usp_connects.append((
                        t, r.group(1), a.group(1) if a else "?",
                        split_remote(rem.group(1))[0] if rem else "-",
                    ))
                    continue
                r = OWN_CRED.search(body)
                if r:
                    dev = re.search(r"\bdevice=(\S+)", body)
                    own_cred.append((t, r.group(1), dev.group(1) if dev else "-"))
                    continue
                r = API_FAILED.search(body)
                if r:
                    api_failed.append((t, r.group(1), norm_ip(r.group(2))))
                    continue
                if SSO_FAILED.search(body):
                    other_notes["single sign-on failures"] += 1
                elif CROSS_ORIGIN.search(body):
                    other_notes["cross-origin change requests refused"] += 1
                elif BLOCKING.search(body):
                    other_notes["sources blocked after repeated CPE authentication failures"] += 1

AUTH_REASONS = {
    "cwmp": {"auth_failed", "auth_blocked"},
    "xmpp": {"auth_failed", "auth_locked"},
    "usp_mqtt": {"credentials"},
    "usp_stomp": {"bad_login"},
}

# ---------------------------------------------------------------- Apache
WEB_RE = re.compile(
    r'^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3}) (\S+)(?: "[^"]*" "([^"]*)")?'
)
VHOST_RE = re.compile(
    r'^\S+:\d+ (\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3}) (\S+)(?: "[^"]*" "([^"]*)")?'
)
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
APACHE_TS = re.compile(r"(\d\d)/(\w{3})/(\d{4}):(\d\d):(\d\d):(\d\d) ([+-])(\d\d)(\d\d)")


def apache_epoch(text):
    m = APACHE_TS.match(text)
    if not m or m.group(2) not in MONTHS:
        return None
    d, mon, y, h, mi, s, sign, oh, om = m.groups()
    offset = datetime.timedelta(hours=int(oh), minutes=int(om))
    if sign == "-":
        offset = -offset
    dt = datetime.datetime(int(y), MONTHS[mon], int(d), int(h), int(mi), int(s),
                           tzinfo=datetime.timezone(offset))
    return int(dt.timestamp())


web = []  # dicts: t, ip, method, path, status
web_files, web_skipped = [], []
web_note = ""
if not os.path.isdir(APACHE_DIR) or not os.access(APACHE_DIR, os.R_OK | os.X_OK):
    web_note = f"skipped: {APACHE_DIR} is not readable"
else:
    for name in sorted(os.listdir(APACHE_DIR)):
        if "access" not in name or ".log" not in name:
            continue
        path = os.path.join(APACHE_DIR, name)
        if not readable(path):
            web_skipped.append(f"{name} (not readable)")
            continue
        if not fresh(path):
            web_skipped.append(f"{name} (older than the window)")
            continue
        web_files.append(name)
        try:
            with open_text(path) as fh:
                for raw in fh:
                    m = WEB_RE.match(raw)
                    if not m or as_ip(m.group(1)) is None:
                        m = VHOST_RE.match(raw)
                    if not m:
                        continue
                    t = apache_epoch(m.group(2))
                    if t is None or not SINCE <= t < UNTIL:
                        continue
                    request = m.group(3).split(" ")
                    web.append({
                        "t": t, "ip": norm_ip(m.group(1)),
                        "method": request[0] if request else "-",
                        "path": request[1] if len(request) > 1 else "-",
                        "status": m.group(4),
                    })
        except (OSError, EOFError) as e:
            web_skipped.append(f"{name} ({e.__class__.__name__}: unreadable)")

# ---------------------------------------------------------------- firewall
UFW_SRC = re.compile(r"\bSRC=(\S+)")
UFW_DPT = re.compile(r"\bDPT=(\d+)")
UFW_PROTO = re.compile(r"\bPROTO=(\S+)")
ufw = []  # (t, src, proto, dport)
try:
    with open(UFW_FILE, "rt", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            head, _, rest = line.partition(" ")
            try:
                t = int(float(head))
            except ValueError:
                continue
            if not SINCE <= t < UNTIL:
                continue
            s, p, d = UFW_SRC.search(rest), UFW_PROTO.search(rest), UFW_DPT.search(rest)
            if s:
                ufw.append((t, norm_ip(s.group(1)), p.group(1) if p else "?",
                            d.group(1) if d else "-"))
except OSError:
    pass

# ---------------------------------------------------------------- derived data
ref_by_ip = collections.defaultdict(lambda: {"count": 0, "listeners": set(), "times": []})
for e in refusals:
    d = ref_by_ip[e["ip"]]
    d["count"] += e["count"]
    d["listeners"].add(e["listener"])
    d["times"].append(e["t"])
total_refusals = sum(e["count"] for e in refusals)

attention = []

# 1. authentication failures from addresses that are not known devices
auth_fail = collections.defaultdict(lambda: {"count": 0, "reasons": set(), "names": set(), "times": []})
for e in refusals:
    if e["reason"] in AUTH_REASONS.get(e["listener"], ()) and not within(e["ip"], KNOWN):
        d = auth_fail[(e["listener"], e["ip"])]
        d["count"] += e["count"]
        d["reasons"].add(e["reason"])
        d["times"].append(e["t"])
        if e["username"]:
            d["names"].add(clean(e["username"], 40))
for (listener, ip), d in sorted(auth_fail.items(), key=lambda kv: -kv[1]["count"]):
    first, last = first_last(d["times"])
    names = ""
    if d["names"]:
        shown = sorted(d["names"])[:5]
        names = " usernames: " + ", ".join(shown) + (" ..." if len(d["names"]) > 5 else "")
    attention.append(
        f"{listener} authentication failure from {label(ip)}: {d['count']} time(s) "
        f"({', '.join(sorted(d['reasons']))}), {first} .. {last}.{names}"
    )

# 2. successful UI/API login from a non-lab address
LOGIN_PATH = re.compile(r"^/api/v1/auth/login(?:[/?]|$)")
ui_logins = [w for w in web if w["method"] == "POST" and LOGIN_PATH.match(w["path"])]
for w in ui_logins:
    if w["status"].startswith("2") and not within(w["ip"], LAB):
        attention.append(
            f"UI/API login succeeded from {w['ip']} at {stamp(w['t'])} "
            f"(POST {clean(w['path'], 60)} -> {w['status']})"
        )

# 3. successful XMPP / USP logins from addresses that are neither known nor lab
for t, account, ip in xmpp_logins:
    if not within(ip, KNOWN) and not within(ip, LAB):
        attention.append(f"XMPP login of '{clean(account, 40)}' accepted from {ip} at {stamp(t)}")
for t, kind, agent, ip in usp_connects:
    if ip != "-" and not within(ip, KNOWN) and not within(ip, LAB):
        attention.append(f"USP {kind} Agent '{clean(agent, 60)}' connected from {ip} at {stamp(t)}")

# 4. a source with more than 100 refusals
for ip, d in sorted(ref_by_ip.items(), key=lambda kv: -kv[1]["count"]):
    if d["count"] > 100:
        first, last = first_last(d["times"])
        attention.append(
            f"{label(ip)} was refused {d['count']} times ({', '.join(sorted(d['listeners']))}), "
            f"{first} .. {last}"
        )

# ---------------------------------------------------------------- output
out = []
p = out.append

p(f"Dhonomos security report for {HOST}")
p(f"Window: {window_text()}")
p(f"Generated: {stamp(datetime.datetime.now().timestamp())}")
p(f"Known device addresses: {KNOWN_SPEC or '-'}   Lab networks (web section): {LAB_SPEC}")
p("")
p("== Attention ==")
if attention:
    for a in attention:
        p(f"  ! {a}")
else:
    p("  Nothing needs attention: no authentication failure from an unknown address, no UI/API")
    p("  login from outside the lab, no source with more than 100 refusals.")
p("")

# ---- 1
p("== 1. Dhonomos refusals ==")
p(f"Log files read: {', '.join(log_files) if log_files else 'none'}" + skipped_text(log_skipped))
if not os.path.isdir(LOG_DIR):
    p(f"  {LOG_DIR} does not exist.")
logged = sum(1 for e in refusals if not e.get("flush"))
p(f"Lines in the window: {log_lines_in_window}; refusal lines: {logged}"
  f" (+{flushes} 'refusals suppressed' line(s)); refusals counted with repeats: {total_refusals}")
if refusals:
    first, last = first_last([e["t"] for e in refusals])
    p(f"First seen: {first}   Last seen: {last}")
    p("")
    by_listener = collections.defaultdict(lambda: [0, set()])
    by_reason = collections.defaultdict(lambda: [0, set()])
    for e in refusals:
        for table_, key in ((by_listener, e["listener"]), (by_reason, (e["listener"], e["reason"]))):
            table_[key][0] += e["count"]
            table_[key][1].add(e["ip"])
    p("By listener:")
    out.extend(table(
        [(k, v[0], len(v[1])) for k, v in sorted(by_listener.items(), key=lambda kv: -kv[1][0])],
        ["listener", "refusals", "sources"]))
    p("")
    p("By listener and reason:")
    out.extend(table(
        [(k[0], k[1], v[0], len(v[1]))
         for k, v in sorted(by_reason.items(), key=lambda kv: -kv[1][0])],
        ["listener", "reason", "refusals", "sources"]))
    p("")
    p(f"Top {TOP} source addresses:")
    rows = []
    for ip, d in sorted(ref_by_ip.items(), key=lambda kv: -kv[1]["count"])[:TOP]:
        f_, l_ = first_last(d["times"])
        rows.append((label(ip), d["count"], ",".join(sorted(d["listeners"])), f_, l_))
    out.extend(table(rows, ["source", "refusals", "listeners", "first seen", "last seen"]))
    names = collections.defaultdict(lambda: {"lines": 0, "ips": set()})
    for e in refusals:
        if e["username"] is not None:
            n = names[(e["listener"], clean(e["username"], 64))]
            n["lines"] += 1
            n["ips"].add(e["ip"])
    p("")
    p(f"Usernames tried (top {TOP}; only logged lines carry a name, repeats are not counted):")
    if names:
        out.extend(table(
            [(k[0], k[1], v["lines"], len(v["ips"]))
             for k, v in sorted(names.items(), key=lambda kv: -kv[1]["lines"])[:TOP]],
            ["listener", "username", "lines", "sources"]))
    else:
        p("  none")
else:
    p("")
    p("  No refusal lines in the window. (The server writes them since the logging of refusals")
    p("  was added; logs of an older run have none, and a restart is needed to get them.)")
p("")
p("API/UI failed logins (warn 'failed login' lines):")
if api_failed:
    ips = collections.Counter(ip for _, _, ip in api_failed)
    names = collections.Counter(u for _, u, _ in api_failed)
    p(f"  {len(api_failed)} failed login(s), {len(ips)} address(es), {len(names)} username(s); "
      f"{first_last([t for t, _, _ in api_failed])[0]} .. {first_last([t for t, _, _ in api_failed])[1]}")
    out.extend(table([(label(ip), n) for ip, n in top(ips, 10)], ["client", "failures"]))
    out.extend(table([(clean(u, 40), n) for u, n in top(names, 10)], ["username", "failures"]))
else:
    p("  none")
for text, n in other_notes.items():
    p(f"  Also logged: {n} {text}")
p("")

# ---- 2
p("== 2. Logins and credentials of note (successes) ==")
p("Dhonomos writes no log line for a successful UI/API login (it is in the audit log and, behind")
p("Apache, in section 3); XMPP logins and USP connections are listed here with their source.")
p("")
p("XMPP logins accepted:")
if xmpp_logins:
    agg = collections.defaultdict(list)
    for t, account, ip in xmpp_logins:
        agg[(clean(account, 40), ip)].append(t)
    rows = []
    for (account, ip), ts in sorted(agg.items(), key=lambda kv: -len(kv[1]))[:MAX_LINES]:
        f_, l_ = first_last(ts)
        rows.append((account, label(ip), len(ts), f_, l_))
    out.extend(table(rows, ["account", "source", "logins", "first", "last"]))
else:
    p("  none logged (the 'XMPP login accepted' line exists in builds after the refusal logging)")
p("")
p("USP Agents connected:")
if usp_connects:
    agg = collections.defaultdict(list)
    for t, kind, agent, ip in usp_connects:
        agg[(kind, clean(agent, 60), ip)].append(t)
    rows = []
    for (kind, agent, ip), ts in sorted(agg.items(), key=lambda kv: -len(kv[1]))[:MAX_LINES]:
        f_, l_ = first_last(ts)
        rows.append((kind, agent, label(ip) if ip != "-" else "-", len(ts), f_, l_))
    out.extend(table(rows, ["mtp", "agent", "source", "connects", "first", "last"]))
else:
    p("  none")
p("")
p("CWMP per-device credentials activated:")
if own_cred:
    for t, text, dev in own_cred[:MAX_LINES]:
        p(f"  {stamp(t)}  {text}  device={clean(dev, 40)}")
    if len(own_cred) > MAX_LINES:
        p(f"  ... and {len(own_cred) - MAX_LINES} more")
else:
    p("  none")
p("")

# ---- 3
p("== 3. Web (Apache access logs) ==")
if web_note:
    p(f"  {web_note}")
else:
    p(f"Files read: {', '.join(web_files) if web_files else 'none'}" + skipped_text(web_skipped))
    outside = [w for w in web if not within(w["ip"], LAB)]
    p(f"Requests in the window: {len(web)}; from outside the lab: {len(outside)}"
      f" ({len({w['ip'] for w in outside})} address(es))")
    if outside:
        p("")
        p(f"Top {TOP} outside addresses:")
        per_ip = collections.defaultdict(lambda: {"n": 0, "status": collections.Counter(), "t": []})
        for w in outside:
            d = per_ip[w["ip"]]
            d["n"] += 1
            d["status"][w["status"][0] + "xx"] += 1
            d["t"].append(w["t"])
        rows = []
        for ip, d in sorted(per_ip.items(), key=lambda kv: -kv[1]["n"])[:TOP]:
            f_, l_ = first_last(d["t"])
            rows.append((ip, d["n"], " ".join(f"{k}:{v}" for k, v in sorted(d["status"].items())), f_, l_))
        out.extend(table(rows, ["address", "requests", "status", "first seen", "last seen"]))
        p("")
        p("Status codes (outside addresses):")
        st = collections.Counter(w["status"] for w in outside)
        p("  " + "  ".join(f"{k}:{v}" for k, v in sorted(st.items())))
        p("")
        p(f"Top {TOP} paths answered 404 (outside addresses):")
        nf = collections.Counter(clean(w["path"], 100) for w in outside if w["status"] == "404")
        if nf:
            out.extend(table([(n, path) for path, n in top(nf)], ["hits", "path"]))
        else:
            p("  none")
    p("")
    p("Login and /api/v1/auth requests (all addresses, POST; lab addresses marked):")
    logins = [w for w in web if w["method"] == "POST"
              and ("/api/v1/auth" in w["path"] or "login" in w["path"].lower())]
    if logins:
        agg = collections.defaultdict(lambda: {"n": 0, "t": []})
        for w in logins:
            d = agg[(w["ip"], clean(w["path"].split("?")[0], 60), w["status"])]
            d["n"] += 1
            d["t"].append(w["t"])
        rows = []
        for (ip, path, status), d in sorted(agg.items(), key=lambda kv: (within(kv[0][0], LAB), -kv[1]["n"]))[:MAX_LINES]:
            f_, l_ = first_last(d["t"])
            rows.append((label(ip) if within(ip, LAB) else ip, path, status, d["n"], f_, l_))
        out.extend(table(rows, ["address", "path", "status", "requests", "first", "last"]))
        if len(agg) > MAX_LINES:
            p(f"  ... and {len(agg) - MAX_LINES} more combination(s)")
    else:
        p("  none")
p("")

# ---- 4
p(f"== 4. Firewall (UFW BLOCK on {WAN_IF or 'all interfaces'}) ==")
p(f"Source: {UFW_NOTE}")
if ufw:
    srcs = collections.Counter(s for _, s, _, _ in ufw)
    ports = collections.Counter((proto, dpt) for _, _, proto, dpt in ufw)
    p(f"Blocked packets: {len(ufw)} from {len(srcs)} address(es)")
    p("")
    p("Top destination ports:")
    SERVICES = {
        "22": "ssh", "80": "http", "443": "https", "1883": "mqtt", "3478": "stun",
        "5222": "xmpp", "7547": "acs", "7548": "files", "7549": "usp-ws", "8080": "api",
        "8883": "mqtt-tls", "61614": "stomp",
    }
    PROTOCOLS = {"1": "ICMP", "2": "IGMP", "41": "IPv6", "47": "GRE", "50": "ESP"}
    out.extend(table(
        [((f"{proto}/{dpt}" if dpt != "-" else PROTOCOLS.get(proto, f"protocol {proto}")),
          n, SERVICES.get(dpt, "")) for (proto, dpt), n in top(ports, 15)],
        ["port", "packets", "service"]))
    p("")
    p("Top sources:")
    src_ports = collections.defaultdict(set)
    src_times = collections.defaultdict(list)
    for t, s, _, dpt in ufw:
        src_ports[s].add(dpt)
        src_times[s].append(t)
    rows = []
    for s, n in top(srcs, 15):
        f_, l_ = first_last(src_times[s])
        rows.append((label(s) if within(s, KNOWN) or within(s, LAB) else s, n, len(src_ports[s]), f_, l_))
    out.extend(table(rows, ["source", "packets", "ports", "first seen", "last seen"]))
else:
    p("  no blocked packets to report")
p("")
p("End of report.")
sys.stdout.write("\n".join(out) + "\n")
PY
status=$?
if [[ $status -ne 0 ]]; then
  echo "security-report: the report program failed (status $status)" >&2
  exit 1
fi
