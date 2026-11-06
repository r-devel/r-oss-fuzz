#!/usr/bin/env python3
"""Summarize the r project's state on OSS-Fuzz.

Prints each target's throughput and how its fuzzing sessions ended over
the last few days, worst first, then the open testcases with their
target, reproducibility and latest task.  A target whose sessions keep
ending in timeouts or out-of-memory exits is finding something (or
wasting most of its time) long before ClusterFuzz files a testcase,
since all of a target's timeouts collapse into one.

The data comes from the JSON endpoints behind the ClusterFuzz dashboard
pages (Fuzzer Statistics, Testcases), which need a logged-in session:
the value of the oss-fuzz.com "session" cookie, read from
$OSSFUZZ_SESSION_FILE or ~/.config/ossfuzz/session.  Only read requests
are made.  These endpoints are not a public API and may change.

Usage:
    scripts/ossfuzz-status.py [--days N] [--engine libfuzzer|afl]
                              [--no-testcases]
"""

import argparse
import concurrent.futures
import datetime
import json
import os
import re
import sys
import urllib.parse
import urllib.request

BASE = "https://oss-fuzz.com"
PROJECT = "r"
JOBS = {
    "libfuzzer": ("libFuzzer", "libfuzzer_asan_r"),
    "afl": ("afl", "afl_asan_r"),
}

# A target is flagged when this share of its sessions ended this way.
FLAG_PERCENT = 1.0


class SessionError(Exception):
    pass


def read_session():
    path = os.environ.get(
        "OSSFUZZ_SESSION_FILE",
        os.path.expanduser("~/.config/ossfuzz/session"),
    )
    try:
        with open(path) as f:
            value = f.read().strip().strip('"')
    except OSError as e:
        raise SessionError(f"cannot read the session cookie: {e}")

    # DevTools can copy a long value with an ellipsis in the middle.
    if not value or not value.isascii():
        raise SessionError(f"{path} does not hold a plain cookie value")
    if value.startswith("session="):
        return value
    return "session=" + value


def request(cookie, path, body=None):
    data = None
    headers = {"Cookie": cookie}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(BASE + path, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read().decode("utf-8", errors="replace")


def request_json(cookie, path, body):
    text = request(cookie, path, body)
    try:
        return json.loads(text)
    except ValueError:
        # An expired or rejected session lands on the login page.
        raise SessionError(
            f"{path} did not return JSON; is the session cookie still valid?"
        )


def csrf_token(cookie):
    page = request(cookie, "/testcases?project=" + PROJECT)
    match = re.search(r"csrf_token=([^\"&]+)", page)
    if match is None:
        raise SessionError("no CSRF token on the testcases page; logged in?")
    return urllib.parse.unquote(match.group(1))


def cell(row, cols, label):
    """The raw and formatted values of one column of a stats row."""
    if label not in cols:
        return None, None
    c = row["c"][cols[label]]
    if c is None:
        return None, None
    return c.get("v"), c.get("f")


def number(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def metric(row, cols, label):
    """A numeric column, or None where this engine does not report it
    (AFL has no fuzzing time, OOM or leak shares)."""
    if label not in cols:
        return None
    return number(cell(row, cols, label)[0])


def percent(value):
    return "--" if value is None else f"{value:.1f}"


def target_name(fuzzer):
    # libFuzzer_r_parse -> parse, afl_r_parse -> parse
    return re.sub(r"^(libFuzzer|afl)_r_", "", fuzzer or "")


def load_stats(cookie, token, engine, date_start, date_end):
    fuzzer, job = JOBS[engine]
    data = request_json(cookie, "/fuzzer-stats/load", {
        "project": PROJECT,
        "fuzzer": fuzzer,
        "job": job,
        "group_by": "by-fuzzer",
        "date_start": date_start.isoformat(),
        "date_end": date_end.isoformat(),
        "csrf_token": token,
    })
    cols = {c["label"]: i for i, c in enumerate(data.get("cols", []))}

    rows = []
    for row in data.get("rows", []):
        raw, formatted = cell(row, cols, "edge_coverage")
        match = re.match(r"\s*([0-9.]+%)", formatted or "")
        edges = match.group(1) if match else raw

        rows.append({
            "target": target_name(cell(row, cols, "fuzzer")[0]),
            "exec_per_sec": metric(row, cols, "avg_exec_per_sec") or 0.0,
            "fuzzing_time": metric(row, cols, "fuzzing_time_percent"),
            "timeout": metric(row, cols, "timeout_percent"),
            "oom": metric(row, cols, "oom_percent"),
            "crash": metric(row, cols, "regular_crash_percent"),
            "leak": metric(row, cols, "leak_percent"),
            "startup": metric(row, cols, "startup_crash_percent"),
            "new_crashes": int(metric(row, cols, "new_crashes") or 0),
            "edges": edges or "--",
        })
    return rows


def flags(row):
    out = []
    for key, word in (("timeout", "timeouts"), ("oom", "ooms"),
                      ("crash", "crashes"), ("leak", "leaks"),
                      ("startup", "startup")):
        if (row[key] or 0.0) >= FLAG_PERCENT:
            out.append(word)
    return out


def print_table(header, rows, right):
    widths = [max(len(str(r[i])) for r in [header] + rows)
              for i in range(len(header))]
    for r in [header] + rows:
        cells = []
        for i, value in enumerate(r):
            text = str(value)
            if i in right:
                cells.append(text.rjust(widths[i]))
            else:
                cells.append(text.ljust(widths[i]))
        print("  ".join(cells).rstrip())


def print_stats(rows, engine, date_start, date_end):
    print(f"{JOBS[engine][1]}, {date_start} to {date_end} "
          f"(percent of fuzzing sessions ending each way)")
    if not rows:
        print("  no statistics for this range")
        return

    bad = ("timeout", "oom", "crash", "leak", "startup")
    rows.sort(key=lambda r: (-sum(r[k] or 0.0 for k in bad),
                             r["exec_per_sec"]))
    table = []
    for r in rows:
        table.append([
            r["target"], f"{r['exec_per_sec']:.1f}",
            percent(r["fuzzing_time"]), percent(r["timeout"]),
            percent(r["oom"]), percent(r["crash"]),
            r["new_crashes"], r["edges"], ", ".join(flags(r)),
        ])
    print_table(
        ["target", "exec/s", "fuzz%", "timeout%", "oom%", "crash%", "new",
         "edges", "flags"],
        table, right={1, 2, 3, 4, 5, 6, 7},
    )


def load_testcases(cookie, token):
    items = []
    page = 1
    while True:
        data = request_json(cookie, "/testcases/load", {
            "project": PROJECT,
            "open": "yes",
            "page": page,
            "csrf_token": token,
        })
        items.extend(data.get("items", []))
        if not data.get("hasMore"):
            break
        page += 1
    return items


def last_task(comments):
    # "[2026-11-05 07:11:38 UTC] worker: Progression task started."
    lines = [l for l in (comments or "").splitlines() if l.strip()]
    if not lines:
        return ""
    match = re.match(r"\[(\d{4}-\d\d-\d\d) [^\]]*\] [^:]+: (.*)", lines[-1])
    if match is None:
        return lines[-1][:60]
    task = match.group(2)
    if task.startswith("Fuzz task"):
        task = "found by fuzzing"
    return f"{match.group(1)[5:]} {task}"[:60]


def print_testcases(cookie, token):
    items = load_testcases(cookie, token)
    print(f"Open testcases ({len(items)})")
    if not items:
        return

    # The list lacks the fuzzer and the task history; each detail request
    # takes seconds, so they go out together.
    items.sort(key=lambda t: -t.get("timestamp", 0))
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        details = list(pool.map(
            lambda t: request_json(cookie, "/testcase-detail/refresh",
                                   {"testcaseId": t["id"]}),
            items))

    table = []
    for item, detail in zip(items, details):
        testcase = detail.get("testcase", {})
        fuzzer = testcase.get("overridden_fuzzer_name") or ""
        target = target_name(fuzzer)
        if fuzzer.startswith("afl"):
            target += " (afl)"
        created = datetime.datetime.fromtimestamp(
            item.get("timestamp", 0), datetime.timezone.utc)

        # Timeouts and OOMs carry the target as their whole state.
        state = " / ".join(item.get("crashStateLines") or [])
        if state == target_name(fuzzer):
            state = ""

        table.append([
            item["id"], created.strftime("%m-%d"), target,
            item.get("crashType", ""), state[:40],
            "yes" if item.get("isReproducible") else "no",
            "yes" if item.get("isSecurity") else "",
            last_task(testcase.get("comments")),
        ])
    print_table(
        ["id", "created", "target", "type", "state", "repro", "sec",
         "latest task"],
        table, right=set(),
    )


def main():
    parser = argparse.ArgumentParser(
        description="Summarize the r project's state on OSS-Fuzz.")
    parser.add_argument("--days", type=int, default=2,
                        help="days of statistics, ending today (default 2)")
    parser.add_argument("--engine", choices=sorted(JOBS), default="libfuzzer")
    parser.add_argument("--no-testcases", action="store_true",
                        help="skip the open testcases")
    args = parser.parse_args()

    date_end = datetime.datetime.now(datetime.timezone.utc).date()
    date_start = date_end - datetime.timedelta(days=max(args.days, 1) - 1)

    try:
        cookie = read_session()
        token = csrf_token(cookie)
        rows = load_stats(cookie, token, args.engine, date_start, date_end)
        print_stats(rows, args.engine, date_start, date_end)
        if not args.no_testcases:
            print()
            print_testcases(cookie, token)
    except SessionError as e:
        print(f"ossfuzz-status: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"ossfuzz-status: request failed: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
