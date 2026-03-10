from __future__ import annotations

import shutil
import os
from pathlib import Path

import yaml

import pytest
from rich.console import Console

from ansible_config_wizard.engine import (
    RedactingConsoleWriter,
    WizardError,
    WizardPaused,
    ask_question,
    build_ssh_setup_commands,
    completed_visible_sections,
    evaluate_condition,
    latest_resume_state_path,
    previous_visible_section_index,
    resolve_field,
    run_wizard,
)
from ansible_config_wizard.models import FieldModel, SectionModel


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


def test_completed_visible_sections_include_current_step() -> None:
    sections = [
        SectionModel(id="one", title="One"),
        SectionModel(id="two", title="Two", when="enabled"),
        SectionModel(id="three", title="Three"),
    ]

    completed = completed_visible_sections(sections, {"enabled": False}, 2)

    assert [(index, step_number, section.id) for index, step_number, section in completed] == [
        (0, 1, "one"),
        (2, 2, "three"),
    ]


def test_latest_resume_state_path_picks_newest(tmp_path: Path) -> None:
    wizard_state_dir = tmp_path / "sample" / "repo"
    older = wizard_state_dir / "runs" / "20260101-000000" / "config-wizard-state.yml"
    newer = wizard_state_dir / "runs" / "20260101-000100" / "config-wizard-state.yml"
    older.parent.mkdir(parents=True, exist_ok=True)
    newer.parent.mkdir(parents=True, exist_ok=True)
    older.write_text("older: true\n", encoding="utf-8")
    newer.write_text("newer: true\n", encoding="utf-8")
    os.utime(older, (1, 1))
    os.utime(newer, (2, 2))

    assert latest_resume_state_path(wizard_state_dir) == newer


def test_resolve_field_reuses_current_value_as_default(monkeypatch, tmp_path: Path) -> None:
    defaults_seen: list[str] = []

    def fake_prompt_field(field, default, console, context):
        defaults_seen.append(default)
        return default

    monkeypatch.setattr("ansible_config_wizard.engine.prompt_field", fake_prompt_field)
    field = FieldModel(id="host_name", label="Host name")
    console = Console(file=Buffer(), force_terminal=False, color_system=None)

    value = resolve_field(
        field,
        {"host_name": "demo-01"},
        provided_value=None,
        current_value="demo-01",
        assume_yes=False,
        console=console,
        repo_root=tmp_path,
    )

    assert value == "demo-01"
    assert defaults_seen == ["demo-01"]


def test_ask_question_saves_progress_on_interrupt(tmp_path: Path, monkeypatch) -> None:
    class InterruptThenAnswer:
        def __init__(self) -> None:
            self.calls = 0

        def ask(self) -> str:
            self.calls += 1
            if self.calls == 1:
                raise KeyboardInterrupt
            return "continue"

    state_path = tmp_path / "config-wizard-state.yml"
    context = {
        "wizard_resume_enabled": True,
        "wizard_resume_state_path": str(state_path),
        "wizard_current_section_index": 2,
    }
    console = Console(file=Buffer(), force_terminal=False, color_system=None)

    answer = ask_question(InterruptThenAnswer(), context, console)

    assert answer == "continue"
    assert state_path.exists()
    saved = yaml.safe_load(state_path.read_text(encoding="utf-8"))
    assert saved["wizard_resume_section_index"] == 2


def test_ask_question_exits_on_second_consecutive_interrupt(tmp_path: Path, monkeypatch) -> None:
    class AlwaysInterrupt:
        def ask(self) -> str:
            raise KeyboardInterrupt

    ticks = iter([10.0, 11.0])
    monkeypatch.setattr("ansible_config_wizard.engine.monotonic", lambda: next(ticks))

    state_path = tmp_path / "config-wizard-state.yml"
    context = {
        "wizard_resume_enabled": True,
        "wizard_resume_state_path": str(state_path),
        "wizard_current_section_index": 1,
    }
    console = Console(file=Buffer(), force_terminal=False, color_system=None)

    with pytest.raises(WizardPaused):
        ask_question(AlwaysInterrupt(), context, console)

    assert state_path.exists()


def test_ask_question_treats_none_as_interrupt(tmp_path: Path, monkeypatch) -> None:
    class NoneThenAnswer:
        def __init__(self) -> None:
            self.calls = 0

        def ask(self) -> str | None:
            self.calls += 1
            if self.calls == 1:
                return None
            return "continue"

    state_path = tmp_path / "config-wizard-state.yml"
    context = {
        "wizard_resume_enabled": True,
        "wizard_resume_state_path": str(state_path),
        "wizard_current_section_index": 3,
    }
    console = Console(file=Buffer(), force_terminal=False, color_system=None)

    answer = ask_question(NoneThenAnswer(), context, console)

    assert answer == "continue"
    assert state_path.exists()
