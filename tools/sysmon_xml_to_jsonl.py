#!/usr/bin/env python3
"""Convert Windows event logs (Sysmon / Security, XML) to JSONL for triagedy.

Real SIEM/Sysmon exports are XML — one <Event> per line. triagedy speaks JSONL.
This is the adapter between them: the same role a collector plays in a real
pipeline (SIEM export → adapter → triagedy → decision queue).

    python3 sysmon_xml_to_jsonl.py windows-sysmon.log > alerts.jsonl
    triagedy run --backend jev < alerts.jsonl

What it does:
  - parses each <Event> line (namespace-agnostic)
  - lifts System fields: EventID, Computer, TimeCreated, Provider, Channel
  - flattens <EventData><Data Name='X'>value</Data> into a dict
  - hoists fields triagedy's parser recognizes (image→process, etc.) to the top
    level while keeping the full nested structure under "event_data"
  - assigns a stable id: <Computer>-<EventRecordID>
  - emits compact JSON, one object per line, skipping unparseable lines (counted
    on stderr, never silently dropped from the count)

Zero dependencies — stdlib only, so it runs anywhere the tool runs.
"""

import json
import sys

# Prefer defusedxml when present (hardened against XXE + billion-laughs);
# fall back to stdlib ElementTree, which does not resolve external entities or
# load DTDs for str input anyway, plus we pre-reject DOCTYPE/ENTITY below.
try:
    from defusedxml import ElementTree as ET  # type: ignore
except ImportError:  # stdlib fallback — still safe for our rejection rule
    import xml.etree.ElementTree as ET  # type: ignore


def localname(tag: str) -> str:
    """'{http://...}EventData' -> 'EventData' (namespaces vary by export)."""
    return tag.rsplit("}", 1)[-1]


def find_all(elem, name):
    for child in elem.iter():
        if localname(child.tag) == name:
            yield child


def parse_event(xml_text: str):
    # Hard reject DTDs/entities: no legitimate Windows event export carries them.
    lowered = xml_text[:2000].lower()
    if "<!doctype" in lowered or "<!entity" in lowered:
        raise ET.ParseError("DTD/entity declarations are not accepted")

    root = ET.fromstring(xml_text)

    system = next(find_all(root, "System"), None)
    event_data = next(find_all(root, "EventData"), None)

    out = {}
    if system is not None:
        evid = next(find_all(system, "EventID"), None)
        if evid is not None and evid.text:
            out["event_id"] = int(evid.text.strip()) if evid.text.strip().isdigit() else evid.text.strip()

        comp = next(find_all(system, "Computer"), None)
        if comp is not None and comp.text:
            out["computer"] = comp.text.strip()

        tc = next(find_all(system, "TimeCreated"), None)
        if tc is not None:
            stamp = tc.get("SystemTime")
            if stamp:
                out["timestamp"] = stamp

        provider = next(find_all(system, "Provider"), None)
        if provider is not None and provider.get("Name"):
            out["provider"] = provider.get("Name")

        channel = next(find_all(system, "Channel"), None)
        if channel is not None and channel.text:
            out["channel"] = channel.text.strip()

        rec = next(find_all(system, "EventRecordID"), None)
        if rec is not None and rec.text:
            out["event_record_id"] = rec.text.strip()

        level = next(find_all(system, "Level"), None)
        if level is not None and level.text:
            out["level"] = level.text.strip()

    data = {}
    if event_data is not None:
        for d in find_all(event_data, "Data"):
            name = d.get("Name")
            if name:
                data[name] = (d.text or "").strip()
    if data:
        out["event_data"] = data

    # Hoist the fields triagedy's parser recognizes, so output records are
    # populated without a second transform.
    def hoist(target, *sources):
        for s in sources:
            if s in data and data[s]:
                out[target] = data[s]
                return

    hoist("process", "Image", "NewProcessName", "ProcessName")
    hoist("command_line", "CommandLine", "ProcessCommandLine")
    hoist("parent_process", "ParentImage", "ParentProcessName")
    hoist("user", "User", "SubjectUserName", "TargetUserName")
    hoist("rule", "RuleName", "Description")
    hoist("src_ip", "SourceIp", "SourceAddress", "IpAddress")
    hoist("dst_ip", "DestinationIp", "DestAddress")

    # Stable id: prefer host + record id, fall back to host + event id.
    host = out.get("computer", "unknown-host")
    rec_id = out.get("event_record_id")
    if rec_id:
        out["id"] = f"{host}-{rec_id}"
    elif "event_id" in out:
        out["id"] = f"{host}-eid{out['event_id']}"

    return out


def main(argv):
    src = open(argv[1], "r", encoding="utf-8", errors="replace") if len(argv) > 1 else sys.stdin
    converted = skipped = 0
    for line in src:
        line = line.strip()
        if not line:
            continue
        try:
            rec = parse_event(line)
        except ET.ParseError:
            skipped += 1
            continue
        print(json.dumps(rec, separators=(",", ":")))
        converted += 1
    print(
        f"converted {converted} events" + (f", skipped {skipped} unparseable lines" if skipped else ""),
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
