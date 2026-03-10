from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from rich.console import Console

from ansible_config_wizard.engine import (
    RedactingConsoleWriter,
    WizardError,
    WizardPaused,
    ask_question,
    build_ssh_setup_commands,
    collect_repeatable,
    configured_vault_password_file,
    configured_vault_password_file_path,
    ensure_vault_password_file,
    encrypt_vault_file,
    initialize_workflow_context,
    install_ssh_key_with_password,
    latest_resume_state_path,
    local_command_choice_default,
    local_command_choice_labels,
    local_command_menu_default,
    local_command_menu_labels,
    persist_progress,
    prompt_for_vault_authentication,
    prompt_for_known_hosts_value,
    reset_following_stage_state,
    resolve_field,
    resolve_local_command_options,
    review_boundary_index,
    run_preflight,
    run_wizard,
    stage_heading,
    stage_label,
    stage_menu_choices,
    stage_state,
    trusted_local_known_hosts_entries,
    visible_stages,
)
from ansible_config_wizard.models import (
    ActionModel,
    FieldModel,
    LocalCommandOptionModel,
    PhaseModel,
    ProfileModel,
    RepeatableModel,
    StageModel,
)


class Buffer:
    def __init__(self) -> None:
        self.parts: list[str] = []

    def write(self, text: str) -> None:
        self.parts.append(text)

    def flush(self) -> None:
        return


def write_interactive_profile(repo_root: Path) -> Path:
    profile_path = repo_root / "wizard_profiles" / "interactive.yml"
    profile_path.parent.mkdir(parents=True, exist_ok=True)
    profile_path.write_text(
        """
id: interactive
name: Interactive Test Profile
builder: wizard_support.builders:build_sample_context
defaults:
  ansible_user: deploy
phases:
  - id: configure
    title: Configure
    stages:
      - id: basics
        title: Basics
        kind: form_stage
        fields:
          - id: host_name
            label: Host name
            required: true
          - id: ansible_host
            label: Ansible host
            required: true
          - id: base_domain
            label: Base domain
            required: true
          - id: vault_demo_password
            label: Demo password
            secret: true
            source:
              kind: generate
              generator: password
              params:
                length: 24
      - id: review
        title: Review
        kind: review_stage
  - id: prepare
    title: Prepare
    stages:
      - id: prepare
        title: Prepare
        kind: command_stage
        allow_skip: true
        actions:
          - kind: local_command
            message_template: Run the prepare command.
            command_template: echo prepare
            prompt: What do you want to do with this stage command?
            available_choices: [show, run, leave]
            default_choice: run
            working_directory_template: "{{ repo_root }}"
  - id: deploy
    title: Deploy
    stages:
      - id: verify
        title: Verification
        kind: manual_stage
        allow_skip: true
        checklist:
          - Confirm the service is reachable.
        confirmation_prompt: When verification is complete, what do you want to do?
outputs:
  - id: hosts
    path: inventories/prod/hosts.yml
    template: wizard_templates/sample/hosts.yml.j2
  - id: all
    path: inventories/prod/group_vars/all.yml
    template: wizard_templates/sample/all.yml.j2
  - id: vault
    path: inventories/prod/group_vars/vault.yml
    template: wizard_templates/sample/vault.yml.j2
    mode: "0600"
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return profile_path


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


def test_trusted_local_known_hosts_entries_filters_ssh_keygen_comments(monkeypatch) -> None:
    expected = "|1|abc|def ssh-ed25519 AAAATEST trusted@example"

    def fake_run(command, check, capture_output, text):
        assert command == ["ssh-keygen", "-F", "[backup.example.com]:2222"]
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="# Host [backup.example.com]:2222 found: line 1\n|1|abc|def ssh-ed25519 AAAATEST trusted@example\n",
            stderr="",
        )

    monkeypatch.setattr("ansible_config_wizard.engine.subprocess.run", fake_run)

    assert trusted_local_known_hosts_entries("backup.example.com", 2222) == [expected]


def test_prompt_for_known_hosts_value_can_reuse_local_trust(monkeypatch) -> None:
    monkeypatch.setattr(
        "ansible_config_wizard.engine.trusted_local_known_hosts_entries",
        lambda host, port: ["|1|abc|def ssh-ed25519 AAAATEST trusted@example"],
    )
    monkeypatch.setattr("ansible_config_wizard.engine.ask_question", lambda *args, **kwargs: "Use keys already trusted in ~/.ssh/known_hosts")

    buffer = Buffer()
    console = Console(file=buffer, force_terminal=False, color_system=None)
    field = FieldModel(id="ssh_known_hosts", label="Pinned SSH host keys", type="multiline_text")

    value = prompt_for_known_hosts_value(field, {}, console, "backup.example.com", 22, None, None)

    assert value == "|1|abc|def ssh-ed25519 AAAATEST trusted@example"


def test_visible_stages_respect_phase_and_stage_conditions() -> None:
    profile = ProfileModel(
        id="demo",
        name="Demo",
        phases=[
            PhaseModel(
                id="configure",
                title="Configure",
                stages=[
                    StageModel(id="host", title="Host", kind="form_stage"),
                    StageModel(id="advanced", title="Advanced", kind="form_stage", when="customize"),
                ],
            ),
            PhaseModel(
                id="deploy",
                title="Deploy",
                when="enabled",
                stages=[StageModel(id="verify", title="Verify", kind="manual_stage")],
            ),
        ],
    )

    entries = visible_stages(profile, {"customize": False, "enabled": True})

    assert [entry["stage"].id for entry in entries] == ["host", "verify"]
    assert stage_heading(entries[0]) == "Phase 1: Configure"
    assert stage_label(entries[1]) == "Stage 2: Verify"


def test_stage_menu_choices_reflect_stage_kind() -> None:
    assert stage_menu_choices(StageModel(id="host", title="Host", kind="form_stage")) == [
        "Continue stage",
        "Return to stage",
        "Save and exit",
        "Exit without saving",
    ]
    assert stage_menu_choices(StageModel(id="prep", title="Prepare", kind="command_stage", allow_skip=True)) == [
        "Run stage",
        "Skip stage",
        "Return to stage",
        "Save and exit",
        "Exit without saving",
    ]


def test_initialize_workflow_context_selects_first_stage() -> None:
    profile = ProfileModel(
        id="demo",
        name="Demo",
        phases=[
            PhaseModel(
                id="configure",
                title="Configure",
                stages=[
                    StageModel(id="host", title="Host", kind="form_stage"),
                    StageModel(id="review", title="Review", kind="review_stage"),
                ],
            )
        ],
    )
    context: dict[str, object] = {}

    entries = initialize_workflow_context(profile, context)

    assert [entry["stage"].id for entry in entries] == ["host", "review"]
    assert context["wizard_current_stage_id"] == "host"
    assert context["wizard_current_phase_id"] == "configure"
    assert stage_state(context, "host") == "not_started"
    assert review_boundary_index(entries) == 1


def test_reset_following_stage_state_resets_only_later_stages() -> None:
    profile = ProfileModel(
        id="demo",
        name="Demo",
        phases=[
            PhaseModel(
                id="configure",
                title="Configure",
                stages=[
                    StageModel(id="host", title="Host", kind="form_stage"),
                    StageModel(id="review", title="Review", kind="review_stage"),
                ],
            ),
            PhaseModel(
                id="deploy",
                title="Deploy",
                stages=[StageModel(id="prepare", title="Prepare", kind="command_stage")],
            ),
        ],
    )
    context = {
        "wizard_stage_states": {
            "host": "completed",
            "review": "completed",
            "prepare": "completed",
        },
        "wizard_stage_step_cursor": {
            "host": 2,
            "review": 1,
            "prepare": 1,
        },
    }
    entries = initialize_workflow_context(profile, context)

    reset_following_stage_state(context, entries, 1)

    assert context["wizard_stage_states"]["host"] == "completed"
    assert context["wizard_stage_states"]["review"] == "not_started"
    assert context["wizard_stage_states"]["prepare"] == "not_started"
    assert context["wizard_stage_step_cursor"]["review"] == 0


def test_persist_progress_writes_stage_state(tmp_path: Path) -> None:
    state_path = tmp_path / "config-wizard-state.yml"
    context = {
        "wizard_resume_enabled": True,
        "wizard_resume_state_path": str(state_path),
        "wizard_current_stage_id": "prepare",
        "wizard_current_phase_id": "deploy",
        "wizard_stage_states": {"review": "completed", "prepare": "in_progress"},
        "wizard_stage_step_cursor": {"review": 1, "prepare": 0},
    }

    persist_progress(context)

    saved = yaml.safe_load(state_path.read_text(encoding="utf-8"))
    assert saved["wizard_current_stage_id"] == "prepare"
    assert saved["wizard_stage_states"]["review"] == "completed"
    assert saved["wizard_stage_step_cursor"]["prepare"] == 0


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


def test_prompt_for_vault_authentication_can_choose_interactive_prompt(monkeypatch, tmp_path: Path) -> None:
    answers = iter(["Prompt for vault password interactively"])
    monkeypatch.setattr("ansible_config_wizard.engine.ask_question", lambda *_args, **_kwargs: next(answers))
    console = Console(file=Buffer(), force_terminal=False, color_system=None)

    result = prompt_for_vault_authentication(tmp_path, None, {}, console)

    assert result is None


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


def test_encrypt_vault_file_uses_explicit_default_vault_id(tmp_path: Path, monkeypatch) -> None:
    repo_root = tmp_path / "repo"
    vault_file = repo_root / "inventories/prod/group_vars/vault.yml"
    vault_file.parent.mkdir(parents=True, exist_ok=True)
    vault_file.write_text("demo: true\n", encoding="utf-8")
    password_file = repo_root / ".vault_pass"
    password_file.write_text("secret\n", encoding="utf-8")
    captured: dict[str, object] = {}

    def fake_run(command, check, cwd):
        captured["command"] = command
        captured["check"] = check
        captured["cwd"] = cwd
        return None

    monkeypatch.setattr("ansible_config_wizard.engine.subprocess.run", fake_run)
    console = Console(file=Buffer(), force_terminal=False, color_system=None)

    encrypt_vault_file(repo_root, password_file, console)

    assert captured["command"] == [
        "ansible-vault",
        "encrypt",
        str(vault_file),
        "--vault-id",
        f"default@{password_file}",
        "--encrypt-vault-id",
        "default",
    ]


def test_evaluate_condition_rejects_unsafe_code() -> None:
    with pytest.raises(WizardError):
        from ansible_config_wizard.engine import evaluate_condition

        evaluate_condition("__import__('os').system('true')", {"enabled": True})


def test_local_command_actions_do_not_write_command_files_by_default() -> None:
    action = ActionModel(
        kind="local_command",
        message_template="Hello",
        command_template="echo hi",
    )

    assert action.write_command_file is False


def test_local_command_action_exposes_profile_defined_choices() -> None:
    action = ActionModel(
        kind="local_command",
        message_template="Hello",
        command_template="echo hi",
        available_choices=["run", "leave"],
        default_choice="run",
    )

    assert local_command_choice_labels(action) == ["Run now", "Skip this step and continue"]
    assert local_command_choice_default(action) == "Run now"


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
        "Skip this step and continue",
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
        resume_command="./scripts/setup.sh --answers-file /tmp/state.yml",
    )

    assert "ssh-copy-id" in commands
    assert "SSH_AUTH_SOCK" in commands
    assert "IdentitiesOnly=yes" in commands
    assert "IdentityAgent=none" in commands
    assert "203.0.113.10" in commands


def test_redacting_console_writer_masks_secrets() -> None:
    output = Buffer()
    console = Console(file=output, force_terminal=False, color_system=None)
    writer = RedactingConsoleWriter(console, secrets=["super-secret"])

    writer.write("password: super-secret\n")

    assert "super-secret" not in "".join(output.parts)
    assert "[redacted]" in "".join(output.parts)


def test_collect_repeatable_can_trim_existing_entries(monkeypatch, tmp_path: Path) -> None:
    repeatable = RepeatableModel(
        id="vaults",
        title="Vaults",
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
        repeatable,
        context,
        answers,
        assume_yes=False,
        console=console,
        repo_root=tmp_path,
        answered_collections=answered_collections,
    )

    assert context["vaults"] == [{"name": "one"}]


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


def test_ask_question_saves_progress_on_interrupt(tmp_path: Path, monkeypatch) -> None:
    class InterruptThenAnswer:
        def __init__(self) -> None:
            self.calls = 0

        def ask(self) -> str:
            self.calls += 1
            if self.calls == 1:
                raise KeyboardInterrupt
            return "continue"

    class FakeSelect:
        def ask(self) -> str:
            return "Save and exit"

    monkeypatch.setattr("ansible_config_wizard.engine.questionary.select", lambda *args, **kwargs: FakeSelect())

    state_path = tmp_path / "config-wizard-state.yml"
    context = {
        "wizard_resume_enabled": True,
        "wizard_resume_state_path": str(state_path),
        "wizard_current_stage_id": "prepare",
        "wizard_stage_states": {"prepare": "in_progress"},
    }
    console = Console(file=Buffer(), force_terminal=False, color_system=None)

    with pytest.raises(WizardPaused):
        ask_question(InterruptThenAnswer(), context, console)
    saved = yaml.safe_load(state_path.read_text(encoding="utf-8"))
    assert saved["wizard_current_stage_id"] == "prepare"


def test_resume_opens_stage_menu_before_running_command(monkeypatch, tmp_path: Path) -> None:
    fixture_root = Path(__file__).parent / "fixture_repo"
    shutil.copytree(fixture_root, tmp_path / "repo", dirs_exist_ok=True)
    repo_root = tmp_path / "repo"
    profile_path = write_interactive_profile(repo_root)
    state_root = tmp_path / "state-home"
    monkeypatch.setenv("ANSIBLE_CONFIG_WIZARD_STATE_HOME", str(state_root))

    first_answers = iter(
        [
            True,
            "Continue stage",
            "demo-01",
            "203.0.113.10",
            "example.com",
            "Continue stage",
            False,
            False,
            "Write files and continue",
            "Save and exit",
        ]
    )
    monkeypatch.setattr("ansible_config_wizard.engine.ask_question", lambda *_args, **_kwargs: next(first_answers))

    with pytest.raises(WizardPaused):
        run_wizard(profile_path=profile_path, repo_root=repo_root)

    resume_path = next(state_root.glob("interactive/repo/runs/*/config-wizard-state.yml"))
    saved = yaml.safe_load(resume_path.read_text(encoding="utf-8"))
    assert saved["wizard_current_stage_id"] == "prepare"
    assert saved["wizard_outputs_written"] is True

    executed: list[object] = []

    def fake_run(*args, **kwargs):
        executed.append((args, kwargs))
        return None

    monkeypatch.setattr("ansible_config_wizard.engine.subprocess.run", fake_run)
    second_answers = iter(["Save and exit"])
    monkeypatch.setattr("ansible_config_wizard.engine.ask_question", lambda *_args, **_kwargs: next(second_answers))

    with pytest.raises(WizardPaused):
        run_wizard(profile_path=profile_path, repo_root=repo_root, answers_path=resume_path)

    assert executed == []


def test_full_interactive_workflow_runs_command_and_manual_stages(monkeypatch, tmp_path: Path) -> None:
    fixture_root = Path(__file__).parent / "fixture_repo"
    shutil.copytree(fixture_root, tmp_path / "repo", dirs_exist_ok=True)
    repo_root = tmp_path / "repo"
    profile_path = write_interactive_profile(repo_root)
    state_root = tmp_path / "state-home"
    monkeypatch.setenv("ANSIBLE_CONFIG_WIZARD_STATE_HOME", str(state_root))

    answers = iter(
        [
            True,
            "Continue stage",
            "demo-01",
            "203.0.113.10",
            "example.com",
            "Continue stage",
            False,
            False,
            "Write files and continue",
            "Run stage",
            "Run now",
            "Run stage",
            "Mark stage complete",
        ]
    )
    monkeypatch.setattr("ansible_config_wizard.engine.ask_question", lambda *_args, **_kwargs: next(answers))
    executed: list[list[str]] = []

    def fake_run(command, *args, **kwargs):
        if isinstance(command, list):
            executed.append(command)
        else:
            executed.append([command])
        return type("Result", (), {"returncode": 0})()

    monkeypatch.setattr("ansible_config_wizard.engine.subprocess.run", fake_run)

    run_wizard(profile_path=profile_path, repo_root=repo_root)

    assert ["echo", "prepare"] in executed
