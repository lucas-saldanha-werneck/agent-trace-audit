from __future__ import annotations

import argparse
import json
import os
import sys

from .audit import audit, load, to_markdown


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="agent-trace-audit",
                                 description="Audit LLM agent traces (JSONL) offline.")
    ap.add_argument("traces", nargs="+", help="JSONL trace files")
    ap.add_argument("--json", action="store_true", help="print JSON instead of Markdown")
    ap.add_argument("--fail-on", choices=["high", "medium", "low"], default="high",
                    help="exit 1 if a finding at this level or above exists (default: high)")
    args = ap.parse_args(argv)
    rank = {"high": 0, "medium": 1, "low": 2}
    worst = 99
    for path in args.traces:
        try:
            report = audit(load(path))
        except (OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        for f in report["findings"]:
            worst = min(worst, rank[f["severity"]])
        name = os.path.basename(path)
        print(json.dumps({name: report}, indent=2) if args.json else to_markdown(name, report))
    return 1 if worst <= rank[args.fail_on] else 0


if __name__ == "__main__":
    sys.exit(main())
