from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from .engine import WizardError, run_wizard

app = typer.Typer(add_completion=False, no_args_is_help=False)


@app.command()
def main(
    profile: Path = typer.Option(..., help="Path to the wizard profile YAML."),
    repo_root: Path = typer.Option(..., help="Path to the target repo root."),
    answers_file: Optional[Path] = typer.Option(None, help="Optional YAML file with pre-seeded answers."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Use defaults or answers file without interactive prompts."),
    encrypt_vault: Optional[bool] = typer.Option(None, "--encrypt-vault/--skip-encrypt-vault", help="Override vault encryption prompt."),
    run_preflight: Optional[bool] = typer.Option(None, "--run-preflight/--skip-preflight", help="Override preflight prompt."),
) -> None:
    try:
        run_wizard(
            profile_path=profile.resolve(),
            repo_root=repo_root.resolve(),
            answers_path=answers_file.resolve() if answers_file else None,
            assume_yes=yes,
            encrypt_override=encrypt_vault,
            preflight_override=run_preflight,
        )
    except WizardError as exc:
        typer.secho(f"ERROR: {exc}", err=True, fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc


if __name__ == "__main__":
    app()
