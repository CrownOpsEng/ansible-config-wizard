from __future__ import annotations

import shutil
from pathlib import Path

import yaml

from ansible_config_wizard.engine import run_wizard


def test_run_wizard_with_external_builder(tmp_path: Path) -> None:
    fixture_root = Path(__file__).parent / "fixture_repo"
    shutil.copytree(fixture_root, tmp_path / "repo", dirs_exist_ok=True)
    repo_root = tmp_path / "repo"

    run_wizard(
        profile_path=repo_root / "wizard_profiles" / "sample.yml",
        repo_root=repo_root,
        answers_path=repo_root / "answers.yml",
        assume_yes=True,
        encrypt_override=False,
        preflight_override=False,
    )

    with (repo_root / "inventories/prod/hosts.yml").open("r", encoding="utf-8") as handle:
        hosts = yaml.safe_load(handle)
    with (repo_root / "inventories/prod/group_vars/all.yml").open("r", encoding="utf-8") as handle:
        all_vars = yaml.safe_load(handle)
    with (repo_root / "inventories/prod/group_vars/vault.yml").open("r", encoding="utf-8") as handle:
        vault_vars = yaml.safe_load(handle)

    assert hosts["all"]["children"]["core_hosts"]["hosts"]["demo-01"]["ansible_user"] == "deploy"
    assert all_vars["base_domain"] == "example.com"
    assert all_vars["derived_domain"] == "ops.example.com"
    assert vault_vars["vault_demo_password"]
