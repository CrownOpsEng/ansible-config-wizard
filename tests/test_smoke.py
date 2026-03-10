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
    collect_repeatable,
    completed_visible_sections,
    describe_next_step,
    describe_step_target,
    evaluate_condition,
    configured_vault_password_file,
    configured_vault_password_file_path,
    ensure_vault_password_file,
    furthest_resume_index,
    install_ssh_key_with_password,
    latest_resume_state_path,
    local_command_choice_default,
    local_command_choice_labels,
    local_command_menu_default,
    local_command_menu_labels,
    next_navigation_choices,
    persist_progress,
    previous_visible_section_index,
    resolve_field,
    resolve_local_command_options,
    run_preflight,
    run_wizard,
)
from ansible_config_wizard.models import ActionModel, FieldModel, LocalCommandOptionModel, SectionModel


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


def test_configured_vault_password_file_uses_ansible_cfg(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    password_file = repo_root / ".secrets" / "vault-pass.txt"
    password_file.parent.mkdir(parents=True)
    password_file.write_text("secret\n", encoding="utf-8")
    (repo_root / "ansible.cfg").write_text(
        "[defaults]\n"
        "vault_password_file = .secrets/vault-pass.txt\n",
        encoding="utf-8",
    )

    assert configured_vault_password_file(repo_root) == password_file.resolve()


def test_configured_vault_password_file_path_reads_missing_default(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (repo_root / "ansible.cfg").write_text(
        "[defaults]\n"
        "vault_password_file = .vault_pass\n",
        encoding="utf-8",
    )

    assert configured_vault_password_file_path(repo_root) == (repo_root / ".vault_pass").resolve()


def test_ensure_vault_password_file_creates_private_file(tmp_path: Path) -> None:
    password_file = tmp_path / ".vault_pass"
    console = Console(file=Buffer(), force_terminal=False, color_system=None)

    created = ensure_vault_password_file(password_file, console)

    assert created == password_file
    assert password_file.exists()
    assert password_file.stat().st_mode & 0o777 == 0o600
    assert len(password_file.read_text(encoding="utf-8").strip()) == 48


def test_run_preflight_uses_ask_vault_pass_for_encrypted_vault(tmp_path: Path, monkeypatch) -> None:
    repo_root = tmp_path / "repo"
    vault_file = repo_root / "inventories/prod/group_vars/vault.yml"
    vault_file.parent.mkdir(parents=True, exist_ok=True)
    vault_file.write_text("$ANSIBLE_VAULT;1.1;AES256\nabcdef\n", encoding="utf-8")
    captured: dict[str, object] = {}

    def fake_run(command, check, cwd):
        captured["command"] = command
        captured["check"] = check
        captured["cwd"] = cwd
        return None

    monkeypatch.setattr("ansible_config_wizard.engine.subprocess.run", fake_run)
    console = Console(file=Buffer(), force_terminal=False, color_system=None)

    run_preflight(repo_root, console)

    assert captured["command"] == [
        "ansible-playbook",
        "-i",
        "inventories/prod/hosts.yml",
        "--ask-vault-pass",
        "playbooks/preflight.yml",
    ]
    assert captured["check"] is True
    assert captured["cwd"] == repo_root


def test_run_preflight_prefers_vault_password_file(tmp_path: Path, monkeypatch) -> None:
    repo_root = tmp_path / "repo"
    vault_file = repo_root / "inventories/prod/group_vars/vault.yml"
    vault_file.parent.mkdir(parents=True, exist_ok=True)
    vault_file.write_text("$ANSIBLE_VAULT;1.1;AES256\nabcdef\n", encoding="utf-8")
    password_file = repo_root / ".secrets" / "vault-pass.txt"
    password_file.parent.mkdir(parents=True, exist_ok=True)
    password_file.write_text("secret\n", encoding="utf-8")
    captured: dict[str, object] = {}

    def fake_run(command, check, cwd):
        captured["command"] = command
        captured["check"] = check
        captured["cwd"] = cwd
        return None

    monkeypatch.setattr("ansible_config_wizard.engine.subprocess.run", fake_run)
    console = Console(file=Buffer(), force_terminal=False, color_system=None)

    run_preflight(repo_root, console, password_file)

    assert captured["command"] == [
        "ansible-playbook",
        "-i",
        "inventories/prod/hosts.yml",
        "--vault-password-file",
        str(password_file),
        "playbooks/preflight.yml",
    ]
    assert captured["check"] is True
    assert captured["cwd"] == repo_root


def test_evaluate_condition_rejects_unsafe_code() -> None:
    with pytest.raises(WizardError):
        evaluate_condition("__import__('os').system('true')", {"enabled": True})


def test_evaluate_condition_supports_attribute_access_for_dicts() -> None:
    assert evaluate_condition("action_item.bootstrap_enabled", {"action_item": {"bootstrap_enabled": True}})


def test_local_command_action_requires_command_template() -> None:
    with pytest.raises(ValueError, match="exactly one of command_template or command_options"):
        ActionModel(kind="local_command", message_template="Hello")


def test_local_command_action_default_choice_must_be_available() -> None:
    with pytest.raises(ValueError, match="default_choice"):
        ActionModel(
            kind="local_command",
            message_template="Hello",
            command_template="echo hi",
            available_choices=["show", "leave"],
            default_choice="run",
        )


def test_local_command_action_exposes_profile_defined_choices() -> None:
    action = ActionModel(
        kind="local_command",
        message_template="Hello",
        command_template="echo hi",
        available_choices=["run", "leave"],
        default_choice="run",
    )

    assert local_command_choice_labels(action) == ["Run now", "Leave for later"]
    assert local_command_choice_default(action) == "Run now"


def test_local_command_actions_do_not_write_command_files_by_default() -> None:
    action = ActionModel(
        kind="local_command",
        message_template="Hello",
        command_template="echo hi",
    )

    assert action.write_command_file is False


def test_local_command_action_accepts_profile_defined_command_options() -> None:
    action = ActionModel(
        kind="local_command",
        message_template="Hello",
        command_options=[
            LocalCommandOptionModel(id="deploy", label="Run deployment", command_template="./scripts/deploy.sh"),
            LocalCommandOptionModel(
                id="prep",
                label="Set up prerequisites",
                command_template="./scripts/setup-prerequisites.sh",
                when="needs_prereqs",
            ),
        ],
    )

    options = resolve_local_command_options(action, {"needs_prereqs": True})

    assert [option["id"] for option in options] == ["deploy", "prep"]


def test_local_command_action_rejects_mixed_single_and_multi_command_config() -> None:
    with pytest.raises(ValueError, match="exactly one of command_template or command_options"):
        ActionModel(
            kind="local_command",
            message_template="Hello",
            command_template="echo hi",
            command_options=[LocalCommandOptionModel(id="deploy", label="Run deployment", command_template="./scripts/deploy.sh")],
        )


def test_local_command_menu_expands_run_choice_into_top_level_options() -> None:
    action = ActionModel(
        kind="local_command",
        message_template="Hello",
        command_options=[
            LocalCommandOptionModel(id="deploy", label="Run deployment", command_template="./scripts/deploy.sh"),
            LocalCommandOptionModel(id="prep", label="Set up prerequisites", command_template="./scripts/setup-prerequisites.sh"),
        ],
        default_choice="run",
    )
    options = resolve_local_command_options(action, {})

    assert local_command_menu_labels(action, options) == [
        "Show commands",
        "Run deployment",
        "Set up prerequisites",
        "Leave for later",
    ]
    assert local_command_menu_default(action, options) == "Run deployment"


def test_install_ssh_key_with_password_rejects_unknown_host_trust(monkeypatch) -> None:
    class FakeSpawn:
        def __init__(self, *_args, **_kwargs) -> None:
            self.before = ""
            self.exitstatus = 255
            self.logfile_read = None

        def expect(self, _patterns) -> int:
            return 0

        def close(self) -> None:
            return

    monkeypatch.setattr("ansible_config_wizard.engine.pexpect.spawn", FakeSpawn)
    console = Console(file=Buffer(), force_terminal=False, color_system=None)

    with pytest.raises(WizardError, match="host key is not trusted locally yet"):
        install_ssh_key_with_password("203.0.113.10", "ubuntu", "/tmp/test.pub", "secret", console)


def test_resolve_field_supports_guided_known_hosts_scan(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "ansible_config_wizard.engine.prompt_for_known_hosts_value",
        lambda field, context, console, host, port, display_default, prompt_default: "backup.example.com ssh-ed25519 AAAA",
    )
    field = FieldModel(
        id="ssh_known_hosts",
        label="Pinned host keys",
        type="multiline_text",
        source={
            "kind": "known_hosts_scan",
            "params": {
                "host_template": "{{ sftp_host }}",
                "port_template": "{{ sftp_port }}",
            },
        },
    )
    console = Console(file=Buffer(), force_terminal=False, color_system=None)

    value = resolve_field(
        field,
        {"sftp_host": "backup.example.com", "sftp_port": 2222},
        provided_value=None,
        current_value=None,
        assume_yes=False,
        console=console,
        repo_root=tmp_path,
    )

    assert value == "backup.example.com ssh-ed25519 AAAA"


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
    defaults_seen: list[tuple[str | None, str | None]] = []

    def fake_prompt_field(field, display_default, prompt_default, console, context):
        defaults_seen.append((display_default, prompt_default))
        return prompt_default

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
    assert defaults_seen == [(None, "demo-01")]


def test_resolve_field_keeps_display_default_when_revisiting(monkeypatch, tmp_path: Path) -> None:
    defaults_seen: list[tuple[str | None, str | None]] = []

    def fake_prompt_field(field, display_default, prompt_default, console, context):
        defaults_seen.append((display_default, prompt_default))
        return prompt_default

    monkeypatch.setattr("ansible_config_wizard.engine.prompt_field", fake_prompt_field)
    field = FieldModel(id="ops_domain", label="Ops domain", default_template="ops.{{ base_domain }}")
    console = Console(file=Buffer(), force_terminal=False, color_system=None)

    value = resolve_field(
        field,
        {"base_domain": "example.com", "ops_domain": "infra.example.com"},
        provided_value=None,
        current_value="infra.example.com",
        assume_yes=False,
        console=console,
        repo_root=tmp_path,
    )

    assert value == "infra.example.com"
    assert defaults_seen == [("ops.example.com", "infra.example.com")]


def test_describe_next_step_uses_following_visible_section() -> None:
    sections = [
        SectionModel(id="one", title="One"),
        SectionModel(id="two", title="Two", when="enabled"),
        SectionModel(id="three", title="Three"),
    ]
    profile = type("Profile", (), {"sections": sections})()

    assert describe_next_step(profile, {"enabled": False}, 0) == "Continue to Step 2: Three"
    assert describe_next_step(profile, {"enabled": True}, 1) == "Continue to Step 3: Three"
    assert describe_next_step(profile, {"enabled": False}, -1) == "Continue to Step 1: One"
    assert describe_step_target(profile, {"enabled": False}, 0) == "Step 2: Three"


def test_persist_progress_preserves_furthest_resume_index(tmp_path: Path) -> None:
    state_path = tmp_path / "config-wizard-state.yml"
    context = {
        "wizard_resume_enabled": True,
        "wizard_resume_state_path": str(state_path),
        "wizard_resume_section_index": 3,
        "wizard_furthest_resume_index": 4,
    }

    persist_progress(context, 2)

    assert furthest_resume_index(context) == 4
    saved = yaml.safe_load(state_path.read_text(encoding="utf-8"))
    assert saved["wizard_resume_section_index"] == 2
    assert saved["wizard_furthest_resume_index"] == 4


def test_next_navigation_choices_prioritize_local_continue() -> None:
    sections = [
        SectionModel(id="one", title="One"),
        SectionModel(id="two", title="Two"),
        SectionModel(id="three", title="Three"),
        SectionModel(id="four", title="Four"),
    ]
    profile = type("Profile", (), {"sections": sections})()
    context = {
        "wizard_resume_section_index": 1,
        "wizard_furthest_resume_index": 3,
    }

    assert next_navigation_choices(profile, context, 1) == [
        "Continue to Step 3: Three",
        "Resume at Step 4: Four",
        "Review a step",
    ]


def test_collect_repeatable_can_trim_existing_entries(monkeypatch, tmp_path: Path) -> None:
    section = SectionModel(
        id="vaults",
        title="Vaults",
        kind="repeatable",
        collection_key="vaults",
        item_label="vault",
        fields=[FieldModel(id="name", label="Vault name")],
    )
    context = {
        "vaults": [
            {"name": "one"},
            {"name": "two"},
            {"name": "three"},
        ]
    }
    answers: dict[str, object] = {}
    console = Console(file=Buffer(), force_terminal=False, color_system=None)
    answered_collections: set[str] = set()
    replies = iter([True, False, False])

    monkeypatch.setattr("ansible_config_wizard.engine.ask_question", lambda prompt, context, console: next(replies))
    monkeypatch.setattr(
        "ansible_config_wizard.engine.resolve_field",
        lambda field, context, provided_value, current_value, assume_yes, console, repo_root: current_value or provided_value or "",
    )

    collect_repeatable(
        section,
        context,
        answers,
        assume_yes=False,
        console=console,
        repo_root=tmp_path,
        answered_collections=answered_collections,
    )

    assert context["vaults"] == [{"name": "one"}]


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
