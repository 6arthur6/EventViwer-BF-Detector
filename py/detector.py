import argparse
import json
import shutil
import subprocess
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


FAIL_ID = 4625
THRESH = 5
WIN_MIN = 10
DEF_HOURS = 24
DEF_MAX = 1000
DEF_IDS = [FAIL_ID]
LOCAL = "LOCAL"
SKIP_SRC = {"-", "127.0.0.1", "::1"}


Ev = dict[str, Any]
Al = dict[str, Any]


def ts(raw: str) -> datetime:
    """parse windows time."""
    # cut extra decimals
    raw = raw.replace("Z", "+00:00")

    if "." in raw:
        date, rest = raw.split(".", 1)

        if "+" in rest:
            frac, tz = rest.split("+", 1)
            raw = f"{date}.{frac[:6]}+{tz}"
        elif "-" in rest:
            frac, tz = rest.split("-", 1)
            raw = f"{date}.{frac[:6]}-{tz}"
        else:
            raw = f"{date}.{rest[:6]}"

    return datetime.fromisoformat(raw)


def add_time(evs: list[Ev]) -> list[Ev]:
    # add time for sort
    for ev in evs:
        ev["parsed_time"] = ts(ev["timestamp"])

    evs.sort(key=lambda ev: ev["parsed_time"])
    return evs


def load_json(path: str | Path) -> list[Ev]:
    # load test data
    path = Path(path)
    if not path.exists():
        raise RuntimeError(f"event file not found: {path}")

    with path.open("r", encoding="utf-8-sig") as fh:
        evs = json.load(fh)

    if isinstance(evs, dict):
        evs = [evs]

    return add_time(evs)


def ps_path() -> str:
    # find powershell
    for exe in ("powershell.exe", "pwsh.exe", "powershell", "pwsh"):
        if shutil.which(exe):
            return exe

    raise RuntimeError(
        "powershell not found"
    )


def ps_script(hours: int, max_evs: int, eids: list[int]) -> str:
    # build the windows log query
    ps_ids = ",".join(str(eid) for eid in eids)

    return f"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$startTime = (Get-Date).AddHours(-{int(hours)})
$filter = @{{ LogName = 'Security'; Id = @({ps_ids}); StartTime = $startTime }}

try {{
    Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop | Out-Null
}} catch [System.UnauthorizedAccessException] {{
    $msg = "no permission to read the Security log. "
    $msg += "run as admin or use an Event Log Readers account."
    throw $msg
}}

try {{
    $rawEvents = Get-WinEvent `
        -FilterHashtable $filter `
        -MaxEvents {int(max_evs)} `
        -ErrorAction Stop
}} catch {{
    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {{
        $rawEvents = @()
    }} else {{
        throw
    }}
}}

$events = $rawEvents | ForEach-Object {{
    [xml]$xml = $_.ToXml()
    $data = @{{}}

    foreach ($item in $xml.Event.EventData.Data) {{
        $data[$item.Name] = $item.'#text'
    }}

    [pscustomobject]@{{
        timestamp = $xml.Event.System.TimeCreated.SystemTime
        event_id = [int]$xml.Event.System.EventID
        computer = $xml.Event.System.Computer
        source_ip = $data['IpAddress']
        target_user = $data['TargetUserName']
        logon_type = $data['LogonType']
        failure_reason = $data['FailureReason']
        workstation_name = $data['WorkstationName']
    }}
}}
@($events) | ConvertTo-Json -Depth 4
"""


def run_ps(cmd: str) -> str:
    ps = ps_path()

    # keep text readable
    res = subprocess.run(
        [ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )

    if res.returncode != 0:
        msg = res.stderr.strip() or res.stdout.strip()
        # make permission errors short
        if "no permission to read the Security log" in msg:
            msg = (
                "no permission to read the Security log. run as admin or use "
                "an Event Log Readers account."
            )
        raise RuntimeError(f"failed to read the Event Viewer Security log: {msg}")

    return res.stdout.strip()


def parse_json(raw: str) -> list[Ev]:
    # support one or many events
    if not raw:
        return []

    evs = json.loads(raw)

    if isinstance(evs, dict):
        evs = [evs]

    return add_time(evs)


def get_sec(
    hours: int,
    max_evs: int,
    eids: list[int],
) -> list[Ev]:
    qry = ps_script(hours, max_evs, eids)
    return parse_json(run_ps(qry))


def src(ev: Ev, local: bool = False) -> str | None:
    # get the event src
    ip = ev.get("source_ip")

    if ip and ip not in SKIP_SRC:
        return ip

    if local:
        ws = ev.get("workstation_name")
        return ws if ws and ws != "-" else LOCAL

    return None


def stats(evs: list[Ev], local: bool = False) -> Ev:
    # count useful failures
    st = {
        "fail_total": 0,
        "fail_used": 0,
        "fail_skipped": 0,
    }

    for ev in evs:
        if ev.get("event_id") != FAIL_ID:
            continue

        st["fail_total"] += 1

        if src(ev, local):
            st["fail_used"] += 1
        else:
            st["fail_skipped"] += 1

    return st


def detect(
    evs: list[Ev],
    local: bool = False,
) -> list[Al]:
    # group failures by src
    by_src: dict[str, list[Ev]] = defaultdict(list)
    als: list[Al] = []

    win = timedelta(minutes=WIN_MIN)

    for ev in evs:
        eid = ev.get("event_id")
        s = src(ev, local)
        t = ev.get("parsed_time")

        if eid != FAIL_ID:
            continue
        if not s:
            continue

        by_src[s].append(ev)

        # keep recent failures
        recent = [
            fail
            for fail in by_src[s]
            if t - fail["parsed_time"] <= win
        ]
        by_src[s] = recent

        if len(recent) >= THRESH:
            # list affected users.
            users = sorted(
                set(fail.get("target_user") for fail in recent)
            )

            al = {
                "type": "brute_force_volume",
                "severity": "high",
                "source": s,
                "source_ip": s,
                "failures": len(recent),
                "threshold": THRESH,
                "window_minutes": WIN_MIN,
                "targeted_users": users,
                "first_seen": recent[0]["timestamp"],
                "last_seen": recent[-1]["timestamp"],
                "description": (
                    f"{s} had {len(recent)} failed logons "
                    f"in {WIN_MIN} minutes."
                ),
            }

            als.append(al)

            # avoid duplicate alerts.
            by_src[s] = []

    return als


def save_json(als: list[Al], path: str | Path) -> None:
    with Path(path).open("w", encoding="utf-8") as fh:
        json.dump(als, fh, indent=4, ensure_ascii=False)


def ids(raw: str) -> list[int]:
    # split the ids from cli
    return [
        int(eid.strip())
        for eid in raw.split(",")
        if eid.strip()
    ]


def cli() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="detect possible brute force attempts in windows event viewer"
    )
    parser.add_argument(
        "--source",
        choices=["windows", "json"],
        default="windows",
        help="event source. default: windows",
    )
    parser.add_argument(
        "--events-file",
        default="events.json",
        help="json file used with --source json",
    )
    parser.add_argument(
        "--alerts-file",
        default="alerts.json",
        help="file where alerts are saved",
    )
    parser.add_argument(
        "--hours",
        type=int,
        default=DEF_HOURS,
        help="hours to search in the Security log",
    )
    parser.add_argument(
        "--max-events",
        type=int,
        default=DEF_MAX,
        help="maximum events returned from Event Viewer",
    )
    parser.add_argument(
        "--event-ids",
        default=",".join(str(eid) for eid in DEF_IDS),
        help="comma separated event ids. default: 4625",
    )
    parser.add_argument(
        "--include-local",
        action="store_true",
        help="include local failures without an ip using workstation_name/local",
    )
    return parser.parse_args()


def main():
    args = cli()

    # choose data src
    if args.source == "json":
        evs = load_json(args.events_file)
    else:
        eids = ids(args.event_ids)
        evs = get_sec(
            args.hours,
            args.max_events,
            eids,
        )

    als = detect(evs, local=args.include_local)
    st = stats(evs, local=args.include_local)

    save_json(als, args.alerts_file)

    print("analysis done.")
    print(f"event source: {args.source}")
    print(f"events checked: {len(evs)}")
    print(f"4625 failures found: {st['fail_total']}")
    print(f"4625 failures used: {st['fail_used']}")
    print(f"4625 local/no-ip failures skipped: {st['fail_skipped']}")
    print(f"alerts created: {len(als)}")

    for al in als:
        print(
            f"[{al['severity'].upper()}] "
            f"{al['type']} - source {al['source']} - "
            f"{al['failures']} failures"
        )


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as err:
        print(f"error: {err}")
        raise SystemExit(1)
