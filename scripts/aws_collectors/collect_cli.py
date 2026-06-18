"""
CLI entrypoint for AWS security telemetry collection.

Usage:
    python -m scripts.aws_collectors.collect_cli --help
    python -m scripts.aws_collectors.collect_cli --collector cloudtrail --region us-east-1
    python -m scripts.aws_collectors.collect_cli --all --output-dir data/collected
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
import structlog

from .cloudtrail_collector import CloudTrailCollector
from .guardduty_collector import GuardDutyCollector
from .iam_collector import IAMCollector
from .security_group_collector import SecurityGroupCollector
from .securityhub_collector import SecurityHubCollector

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer(),
    ]
)

logger = structlog.get_logger(__name__)

COLLECTORS = {
    "cloudtrail": CloudTrailCollector,
    "iam": IAMCollector,
    "security_groups": SecurityGroupCollector,
    "securityhub": SecurityHubCollector,
    "guardduty": GuardDutyCollector,
}


@click.command()
@click.option(
    "--collector",
    type=click.Choice(list(COLLECTORS.keys())),
    default=None,
    help="Run a specific collector.",
)
@click.option("--all", "run_all", is_flag=True, help="Run all collectors.")
@click.option(
    "--region",
    default="us-east-1",
    show_default=True,
    help="AWS region to target.",
)
@click.option(
    "--output-dir",
    type=click.Path(),
    default="data/collected",
    show_default=True,
    help="Directory to write NDJSON output files.",
)
@click.option(
    "--lookback-hours",
    default=24,
    show_default=True,
    help="CloudTrail lookback window in hours.",
)
def main(
    collector: str | None,
    run_all: bool,
    region: str,
    output_dir: str,
    lookback_hours: int,
) -> None:
    """Collect AWS security telemetry using read-only APIs."""
    if not collector and not run_all:
        click.echo("Specify --collector <name> or --all.", err=True)
        sys.exit(1)

    output_path = Path(output_dir)
    names_to_run = list(COLLECTORS.keys()) if run_all else [collector]

    for name in names_to_run:
        cls = COLLECTORS[name]
        kwargs: dict = {"region": region}
        if name == "cloudtrail":
            kwargs["lookback_hours"] = lookback_hours

        instance = cls(**kwargs)
        try:
            result = instance.run(output_dir=output_path)
            click.echo(
                f"[{name}] collected {result.record_count} records"
                + (f" ({len(result.errors)} errors)" if result.errors else "")
            )
        except Exception as exc:
            logger.error("collector_failed", collector=name, error=str(exc))
            click.echo(f"[{name}] FAILED: {exc}", err=True)


if __name__ == "__main__":
    main()
