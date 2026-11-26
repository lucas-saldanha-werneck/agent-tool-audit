from __future__ import annotations

import argparse
import json
import sys

from .audit import audit, load, ERROR, WARN, INFO

ORDER = {ERROR: 0, WARN: 1, INFO: 2}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="agent-tool-audit",
                                 description="Audit MCP tools/list JSON files (offline).")
    ap.add_argument("files", nargs="+")
    ap.add_argument("--json", action="store_true", help="print findings as JSON")
    ap.add_argument("--fail-on", choices=[ERROR, WARN, INFO], default=ERROR,
                    help="exit 1 if a finding at this level or worse exists (default: error)")
    args = ap.parse_args(argv)

    worst = 99
    report = {}
    for path in args.files:
        try:
            findings = audit(load(path))
        except (OSError, ValueError) as e:  # JSONDecodeError is a ValueError
            print(f"{path}: {e}", file=sys.stderr)
            return 2
        findings.sort(key=lambda f: (ORDER[f.severity], f.tool, f.rule))
        report[path] = [f.to_dict() for f in findings]
        for f in findings:
            worst = min(worst, ORDER[f.severity])
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        for path, items in report.items():
            print(f"{path}: {len(items)} finding(s)")
            for f in items:
                print(f"  [{f['severity']}] {f['tool']}: {f['rule']} - {f['message']}")
    return 1 if worst <= ORDER[args.fail_on] else 0


if __name__ == "__main__":
    sys.exit(main())
