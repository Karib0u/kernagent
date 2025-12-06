"""Allow `python -m kernagent` to invoke the CLI."""

from .cli_app import main


def run() -> None:
    main()


if __name__ == "__main__":  # pragma: no cover
    run()
