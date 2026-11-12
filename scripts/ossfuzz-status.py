#!/usr/bin/env python3
"""Summarize the r project's state on OSS-Fuzz.

Prints each target's throughput and how its fuzzing sessions ended over
the last few days, worst first, then the open testcases with their
target, reproducibility and latest task.  A target whose sessions keep
ending in timeouts or out-of-memory exits is finding something (or
wasting most of its time) long before ClusterFuzz files a testcase,
since all of a target's timeouts collapse into one.

The window is whole UTC days ending yesterday: ClusterFuzz publishes a
day's statistics only after it ends, and asks for today alone answer
404.  Columns:

    fuzz%     share of the expected session time actually spent fuzzing
    timeout%, oom%, leak%, crash%
              share of sessions that ended that way
    new       crash signatures first seen in the window
    edges     edge coverage from the daily coverage job, not from these
              sessions; R's startup alone reaches most of it, so compare
              targets against the lowest one rather than against zero

--by-day prints a row per target and day instead of one total per
target, for following a trend across a harness change: the shares vary
a lot from day to day, and a day can mix two builds.  --target limits
the statistics and the testcases to the named targets.

The data comes from the JSON endpoints behind the ClusterFuzz dashboard
pages (Fuzzer Statistics, Testcases), which need a logged-in session:
the value of the oss-fuzz.com "session" cookie, read from
$OSSFUZZ_SESSION_FILE or ~/.config/ossfuzz/session.  Only read requests
are made.  These endpoints are not a public API and may change.

Usage:
    scripts/ossfuzz-status.py [--days N] [--engine libfuzzer|afl]
                              [--by-day] [--target NAME ...]
                              [--no-testcases]
"""

import argparse
import concurrent.futures
import datetime
import http.client
import json
import os
import re
import sys
import urllib.error
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

# Ways a session can end other than running out its time.
BAD_ENDINGS = ("timeout", "oom", "crash", "leak", "startup")

STATS_HEADER = ["exec/s", "fuzz%", "timeout%", "oom%", "leak%", "crash%",
                "new", "edges", "flags"]

REQUEST_ATTEMPTS = 3


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

    # The testcases page (over 1 MB) now and then arrives cut short.
    for attempt in range(REQUEST_ATTEMPTS):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except http.client.IncompleteRead:
            if attempt == REQUEST_ATTEMPTS - 1:
                raise


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
    try:
        data = request_json(cookie, "/fuzzer-stats/load", {
            "project": PROJECT,
            "fuzzer": fuzzer,
            "job": job,
            "group_by": "by-fuzzer",
            "date_start": date_start.isoformat(),
            "date_end": date_end.isoformat(),
            "csrf_token": token,
        })
    except urllib.error.HTTPError as e:
        # A range ClusterFuzz has not published yet answers 404.
        if e.code == 404:
            return []
        raise
    cols ={c["label"]: i for i, c in enumerate(data.get("cols", []))}

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


def load_daily_stats(cookie, token, engine, date_start, date_end):
    """(date, rows) for each day, oldest first.  The endpoint totals over
    its range, so each day is a request of its own."""
    days = [date_start + datetime.timedelta(days=i)
            for i in range((date_end - date_start).days + 1)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        tables = list(pool.map(
            lambda d: load_stats(cookie, token, engine, d, d), days))
    return list(zip(days, tables))


def select(rows, targets):
    if not targets:
        return rows
    return [r for r in rows if r["target"] in targets]


def warn_missing(targets, tables):
    # A misspelled target would otherwise look like a quiet one.
    seen = {r["target"] for rows in tables for r in rows}
    missing = sorted(targets - seen)
    if seen and missing:
        print(f"ossfuzz-status: no statistics for {', '.join(missing)}",
              file=sys.stderr)


def badness(row):
    return sum(row[k] or 0.0 for k in BAD_ENDINGS)


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


def stats_cells(r):
    return [
        f"{r['exec_per_sec']:.1f}",
        percent(r["fuzzing_time"]), percent(r["timeout"]),
        percent(r["oom"]), percent(r["leak"]), percent(r["crash"]),
        r["new_crashes"], r["edges"], ", ".join(flags(r)),
    ]


def print_edges_note(rows):
    covered = [(float(str(r["edges"]).rstrip("%")), r["target"])
               for r in rows if re.fullmatch(r"[0-9.]+%", str(r["edges"]))]
    if not covered:
        return
    note = "edges come from the daily coverage job and are mostly R startup"
    if len(covered) > 1:
        low, target = min(covered)
        note += f"; the lowest is {target} at {low:.2f}%"
    print(note)


def print_stats(rows, engine, date_start, date_end):
    print(f"{JOBS[engine][1]}, {date_start} to {date_end} UTC "
          f"(fuzz%: time spent fuzzing; other %: sessions ending that way)")
    if not rows:
        print("  no statistics for this range")
        return

    rows.sort(key=lambda r: (-badness(r), r["exec_per_sec"]))
    table = [[r["target"]] + stats_cells(r) for r in rows]
    print_table(["target"] + STATS_HEADER, table, right=set(range(1, 9)))
    print_edges_note(rows)


def print_daily_stats(days, engine):
    print(f"{JOBS[engine][1]}, {days[0][0]} to {days[-1][0]} UTC by day "
          f"(fuzz%: time spent fuzzing; other %: sessions ending that way)")

    by_target = {}
    for date, rows in days:
        for r in rows:
            by_target.setdefault(r["target"], []).append((date, r))
    if not by_target:
        print("  no statistics for this range")
        return

    # Worst targets first, ranked on their daily average as in the
    # summary; each target's days stay in date order.
    order = sorted(by_target, key=lambda t: (
        -sum(badness(r) for _, r in by_target[t]) / len(by_target[t]),
        sum(r["exec_per_sec"] for _, r in by_target[t]) / len(by_target[t]),
    ))
    table = []
    for target in order:
        for i, (date, r) in enumerate(by_target[target]):
            label = target if i == 0 else ""
            table.append([label, date.strftime("%m-%d")] + stats_cells(r))
    print_table(["target", "date"] + STATS_HEADER, table,
                right=set(range(2, 10)))

    latest = next((rows for _, rows in reversed(days) if rows), [])
    print_edges_note(latest)


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


def print_testcases(cookie, token, targets):
    items = load_testcases(cookie, token)

    # The list lacks the fuzzer and the task history; each detail request
    # takes seconds, so they go out together.
    items.sort(key=lambda t: -t.get("timestamp", 0))
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        details = list(pool.map(
            lambda t: request_json(cookie, "/testcase-detail/refresh",
                                   {"testcaseId": t["id"]}),
            items))

    pairs = []
    for item, detail in zip(items, details):
        fuzzer = detail.get("testcase", {}).get("overridden_fuzzer_name")
        if not targets or target_name(fuzzer) in targets:
            pairs.append((item, detail))

    print(f"Open testcases ({len(pairs)})")
    if not pairs:
        return

    table = []
    for item, detail in pairs:
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
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--days", type=int, default=2,
                        help="days of statistics, ending yesterday (UTC) "
                             "(default 2)")
    parser.add_argument("--engine", choices=sorted(JOBS), default="libfuzzer")
    parser.add_argument("--by-day", action="store_true",
                        help="a row per target and day instead of totals")
    parser.add_argument("--target", action="append", metavar="NAME",
                        help="only this target, e.g. eval (repeatable)")
    parser.add_argument("--no-testcases", action="store_true",
                        help="skip the open testcases")
    args = parser.parse_args()

    today = datetime.datetime.now(datetime.timezone.utc).date()
    date_end = today - datetime.timedelta(days=1)
    date_start = date_end - datetime.timedelta(days=max(args.days, 1) - 1)

    # Accept ClusterFuzz's fuzzer names (libFuzzer_r_eval) as well.
    targets = {target_name(t) for t in args.target or []}

    try:
        cookie = read_session()
        token = csrf_token(cookie)
        if args.by_day:
            days = load_daily_stats(
                cookie, token, args.engine, date_start, date_end)
            warn_missing(targets, [rows for _, rows in days])
            days = [(d, select(rows, targets)) for d, rows in days]
            print_daily_stats(days, args.engine)
        else:
            rows = load_stats(cookie, token, args.engine, date_start, date_end)
            warn_missing(targets, [rows])
            print_stats(
                select(rows, targets), args.engine, date_start, date_end)

        if not args.no_testcases:
            print()
            print_testcases(cookie, token, targets)
    except SessionError as e:
        print(f"ossfuzz-status: {e}", file=sys.stderr)
        return 1
    except (OSError, http.client.HTTPException) as e:
        print(f"ossfuzz-status: request failed: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
