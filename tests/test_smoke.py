from __future__ import annotations

import shutil
from pathlib import Path

import yaml

import pytest
from rich.console import Console

from ansible_config_wizard.engine import (
    RedactingConsoleWriter,
    WizardError,
    build_ssh_setup_commands,
    evaluate_condition,
    previous_visible_section_index,
    run_wizard,
)
from ansible_config_wizard.models import SectionModel


class Buffer:
    def __init__(self) -> None:
        self.parts: list[str] = []

    def write(self, text: str) -> None:
        self.parts.append(text)

    def flush(self) -> None:
        return


def test_run_wizard_with_external_builder(tmp_path: Path, monkeypatch) -> None:
    fixture_root = Path(__file__).parent / "fixture_repo"
    shutil.copytree(fixture_root, tmp_path / "repo", dirs_exist_ok=True)
    repo_root = tmp_path / "repo"
    state_root = tmp_path / "state-home"
    ssh_root = tmp_path / "ssh-home"
    monkeypatch.setenv("ANSIBLE_CONFIG_WIZARD_STATE_HOME", str(state_root))
    monkeypatch.setenv("ANSIBLE_CONFIG_WIZARD_SSH_HOME", str(ssh_root))

    run_wizard(
        profile_path=repo_root / "wizard_profiles" / "sample.yml",
        repo_root=repo_root,
        answers_path=repo_root / "answers.yml",
        assume_yes=True,
        encrypt_override=False,
        preflight_override=False,
    )
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
    ssh_dir = ssh_root / "repo"
    assert (ssh_dir / "demo-01").exists()
    assert (ssh_dir / "demo-01.pub").exists()
    public_key = (ssh_dir / "demo-01.pub").read_text(encoding="utf-8").strip()
    assert public_key.endswith("deploy@demo-01")
    assert public_key.count("deploy@demo-01") == 1
    assert not any(path.name == "config-wizard-state.yml" for path in state_root.glob("sample/repo/runs/*/config-wizard-state.yml"))


def test_evaluate_condition_rejects_unsafe_code() -> None:
    with pytest.raises(WizardError):
        evaluate_condition("__import__('os').system('true')", {"enabled": True})


def test_build_ssh_setup_commands_disables_agent_keys() -> None:
    commands = build_ssh_setup_commands(
        host="203.0.113.10",
        ssh_user="ubuntu",
        public_key_path="/tmp/test key.pub",
        private_key_path="/tmp/test key",
        resume_command="./scripts/configure.sh --answers-file /tmp/state.yml",
    )

    assert "ssh-copy-id" in commands
    assert "SSH_AUTH_SOCK" in commands
    assert "IdentitiesOnly=yes" in commands
    assert "IdentityAgent=none" in commands
    assert "203.0.113.10" in commands
    assert commands.startswith("env -u SSH_AUTH_SOCK \\\n  ssh-copy-id \\")
    assert "\n  -o 'IdentitiesOnly=yes' \\\n" in commands
    assert "\n  -i '/tmp/test key.pub' \\\n" in commands
    assert "\n  'ubuntu@203.0.113.10'\n" in commands
    assert "\n\nenv -u SSH_AUTH_SOCK \\\n  ssh \\\n" in commands


def test_redacting_console_writer_masks_secrets() -> None:
    output = Buffer()
    console = Console(file=output, force_terminal=False, color_system=None)
    writer = RedactingConsoleWriter(console, secrets=["super-secret"])

    writer.write("password: super-secret\n")

    assert "super-secret" not in "".join(output.parts)
    assert "[redacted]" in "".join(output.parts)


def test_previous_visible_section_index_skips_hidden_sections() -> None:
    sections = [
        SectionModel(id="one", title="One"),
        SectionModel(id="two", title="Two", when="enabled"),
        SectionModel(id="three", title="Three"),
    ]

    assert previous_visible_section_index(sections, {"enabled": False}, 2) == 0
    assert previous_visible_section_index(sections, {"enabled": True}, 2) == 1
