from __future__ import annotations

import ast
import copy
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import questionary
import yaml
from jinja2 import Environment, FileSystemLoader
from rich.console import Console
from rich.panel import Panel

from .generators import generate_value, load_ed25519_keypair
from .models import ActionModel, FieldModel, OutputModel, ProfileModel, SectionModel
from .resolver import resolve_builder
from .writers import atomic_write, backup_existing, secure_delete


class WizardError(RuntimeError):
    pass


class WizardPaused(RuntimeError):
    pass


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip()).strip("-").lower()
    return slug or "default"


def default_state_home() -> Path:
    override = os.environ.get("ANSIBLE_CONFIG_WIZARD_STATE_HOME")
    if override:
        return Path(override).expanduser().resolve()
    xdg_state_home = os.environ.get("XDG_STATE_HOME")
    if xdg_state_home:
        return Path(xdg_state_home).expanduser().resolve() / "ansible-config-wizard"
    return (Path.home() / ".local" / "state" / "ansible-config-wizard").resolve()


def default_ssh_home() -> Path:
    override = os.environ.get("ANSIBLE_CONFIG_WIZARD_SSH_HOME")
    if override:
        return Path(override).expanduser().resolve()
    return (Path.home() / ".ssh" / "ansible-config-wizard").resolve()


def ensure_private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    return path


def load_profile(path: Path) -> ProfileModel:
    with path.open("r", encoding="utf-8") as handle:
        return ProfileModel.model_validate(yaml.safe_load(handle))


def load_answers(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def evaluate_ast_expression(node: ast.AST, context: dict[str, Any]) -> Any:
    if isinstance(node, ast.Expression):
        return evaluate_ast_expression(node.body, context)
    if isinstance(node, ast.Name):
        return context.get(node.id)
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.List):
        return [evaluate_ast_expression(item, context) for item in node.elts]
    if isinstance(node, ast.Tuple):
        return tuple(evaluate_ast_expression(item, context) for item in node.elts)
    if isinstance(node, ast.Dict):
        return {
            evaluate_ast_expression(key, context): evaluate_ast_expression(value, context)
            for key, value in zip(node.keys, node.values, strict=True)
        }
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return not bool(evaluate_ast_expression(node.operand, context))
    if isinstance(node, ast.BoolOp):
        values = [bool(evaluate_ast_expression(value, context)) for value in node.values]
        if isinstance(node.op, ast.And):
            return all(values)
        if isinstance(node.op, ast.Or):
            return any(values)
    if isinstance(node, ast.Compare):
        left = evaluate_ast_expression(node.left, context)
        for operator, comparator in zip(node.ops, node.comparators, strict=True):
            right = evaluate_ast_expression(comparator, context)
            if isinstance(operator, ast.Eq):
                result = left == right
            elif isinstance(operator, ast.NotEq):
                result = left != right
            elif isinstance(operator, ast.In):
                result = left in right
            elif isinstance(operator, ast.NotIn):
                result = left not in right
            elif isinstance(operator, ast.Is):
                result = left is right
            elif isinstance(operator, ast.IsNot):
                result = left is not right
            else:
                raise WizardError(f"Unsupported condition operator: {ast.dump(operator)}")
            if not result:
                return False
            left = right
        return True
    raise WizardError(f"Unsupported condition expression: {ast.dump(node)}")


def evaluate_condition(expression: str | None, context: dict[str, Any]) -> bool:
    if not expression:
        return True
    tree = ast.parse(expression, mode="eval")
    return bool(evaluate_ast_expression(tree, copy.deepcopy(context)))


def render_template_string(template: str | None, context: dict[str, Any]) -> Any:
    if template is None:
        return None
    environment = Environment(autoescape=False)
    return environment.from_string(template).render(**context)


def default_for_field(field: FieldModel, context: dict[str, Any]) -> Any:
    if field.default_template:
        return render_template_string(field.default_template, context)
    return copy.deepcopy(field.default)


def normalize_value(field: FieldModel, value: Any) -> Any:
    if value is None:
        return value
    if field.type == "confirm":
        return bool(value)
    if field.type == "int":
        return int(value)
    if field.type == "list":
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        text = str(value).replace("\n", field.separator)
        return [item.strip() for item in text.split(field.separator) if item.strip()]
    if field.type == "key_value":
        return value or {}
    return value


def prompt_key_value(field: FieldModel, default: dict[str, str] | None, console: Console) -> dict[str, str]:
    default = copy.deepcopy(default or {})
    if default:
        use_default = questionary.confirm(
            f"{field.label}: keep existing/default key-value entries?",
            default=True,
        ).ask()
        if use_default:
            return default

    result: dict[str, str] = {}
    console.print(f"[bold]{field.label}[/bold] (leave key blank to finish)")
    while True:
        key = questionary.text("Key").ask()
        if not key:
            break
        value = questionary.password("Value").ask() if field.secret else questionary.text("Value").ask()
        result[key] = value or ""
    return result


def prompt_field(field: FieldModel, default: Any, console: Console) -> Any:
    prompt = field.label
    if field.help:
        prompt = f"{prompt} ({field.help})"

    if field.type == "confirm":
        return questionary.confirm(prompt, default=bool(default)).ask()
    if field.type == "select":
        return questionary.select(prompt, choices=field.choices, default=default).ask()
    if field.type == "password":
        return questionary.password(prompt, default=str(default or "")).ask()
    if field.type == "int":
        return int(questionary.text(prompt, default=str(default or 0)).ask())
    if field.type == "list":
        default_text = ", ".join(default or [])
        answer = questionary.text(prompt, default=default_text).ask()
        return normalize_value(field, answer)
    if field.type == "key_value":
        return prompt_key_value(field, default, console)
    if field.type == "ssh_keypair":
        return default
    return questionary.text(prompt, default="" if default is None else str(default)).ask()


def materialize_generated_value(
    field: FieldModel,
    value: Any,
    context: dict[str, Any],
    repo_root: Path,
) -> Any:
    if field.type != "ssh_keypair" or not isinstance(value, dict):
        return value

    comment_template = field.source.params.get("comment_template")
    rendered_comment = render_template_string(comment_template, context) if comment_template else None
    if rendered_comment and not value.get("public_key", "").strip().endswith(rendered_comment):
        comment = rendered_comment
        value["public_key"] = f"{value['public_key']} {comment}".strip()
        value["fingerprint"] = value["fingerprint"]

    path_template = field.source.params.get("path_template")
    if not path_template:
        return value

    base_path = Path(render_template_string(path_template, context))
    if not base_path.is_absolute():
        base_path = repo_root / base_path
    ensure_private_dir(base_path.parent)
    public_path = base_path.with_name(f"{base_path.name}.pub")

    atomic_write(base_path, value["private_key"].rstrip() + "\n", 0o600)
    atomic_write(public_path, value["public_key"].rstrip() + "\n", 0o644)

    result = copy.deepcopy(value)
    result["private_key_path"] = str(base_path)
    result["public_key_path"] = str(public_path)
    return result


def resolve_field(
    field: FieldModel,
    context: dict[str, Any],
    provided_value: Any,
    assume_yes: bool,
    console: Console,
    repo_root: Path,
) -> Any:
    default = default_for_field(field, context)
    if provided_value is not None:
        return normalize_value(field, provided_value)

    source = field.source
    if source.kind == "generate":
        generator_params = copy.deepcopy(source.params)
        if field.type == "ssh_keypair":
            path_template = source.params.get("path_template")
            if path_template:
                base_path = Path(render_template_string(path_template, context))
                if not base_path.is_absolute():
                    base_path = repo_root / base_path
                public_path = base_path.with_name(f"{base_path.name}.pub")
                if source.params.get("reuse_existing", True) and base_path.exists():
                    value = load_ed25519_keypair(base_path, public_path)
                    value["private_key_path"] = str(base_path)
                    value["public_key_path"] = str(public_path)
                    console.print(f"[cyan]Using existing[/cyan] {field.label}.")
                    return value
            if source.params.get("comment_template"):
                generator_params["comment"] = render_template_string(source.params["comment_template"], context)
        value = generate_value(source.generator or "password", generator_params)
        value = materialize_generated_value(field, value, context, repo_root)
        console.print(f"[green]Generated[/green] {field.label}.")
        return value

    if source.kind == "external_vault":
        if assume_yes:
            raise WizardError(f"Missing external vault reference for required field: {field.id}")
        driver = questionary.select(
            f"{field.label}: external vault driver",
            choices=["bitwarden", "1password", "vaultwarden", "aws_secrets_manager", "gcp_secret_manager", "hashicorp_vault"],
            default="bitwarden",
        ).ask()
        reference = questionary.text(f"{field.label}: secret reference or ID").ask()
        return {"driver": driver, "ref": {"id": reference or ""}}

    if assume_yes:
        if default not in (None, "", [], {}):
            return normalize_value(field, default)
        if source.kind == "optional_prompt":
            return normalize_value(field, default)
        if field.required:
            raise WizardError(f"Missing value for required field: {field.id}")
        return normalize_value(field, default)

    value = prompt_field(field, default, console)
    if field.required and value in (None, "", [], {}):
        raise WizardError(f"Value required for field: {field.id}")
    return normalize_value(field, value)


def collect_fields(section: SectionModel, context: dict[str, Any], answers: dict[str, Any], assume_yes: bool, console: Console, repo_root: Path) -> None:
    for field in section.fields:
        if not evaluate_condition(field.when, context):
            continue
        provided = answers.get(field.id)
        value = resolve_field(field, context, provided, assume_yes, console, repo_root)
        context[field.id] = value


def collect_repeatable(section: SectionModel, context: dict[str, Any], answers: dict[str, Any], assume_yes: bool, console: Console, repo_root: Path) -> None:
    collection_key = section.collection_key or section.id
    provided_items = answers.get(collection_key)
    items: list[dict[str, Any]] = []

    if provided_items is not None:
        for index, provided_item in enumerate(provided_items, start=1):
            item_context = copy.deepcopy(context)
            item_context["item_index"] = index
            item: dict[str, Any] = {}
            for field in section.fields:
                if not evaluate_condition(field.when, {**item_context, **item}):
                    continue
                item[field.id] = resolve_field(
                    field,
                    {**item_context, **item},
                    provided_item.get(field.id),
                    assume_yes,
                    console,
                    repo_root,
                )
            items.append(item)
        context[collection_key] = items
        return

    if assume_yes and section.default_count == 0 and section.min_items == 0:
        context[collection_key] = []
        return

    count_default = max(section.default_count, section.min_items)
    if assume_yes:
        count = count_default
    else:
        count = int(
            questionary.text(
                f"{section.title}: how many {section.item_label}s?",
                default=str(count_default),
            ).ask()
        )
    count = max(count, section.min_items)

    for index in range(1, count + 1):
        console.print(Panel.fit(f"{section.item_label.title()} {index}", border_style="cyan"))
        item_context = copy.deepcopy(context)
        item_context["item_index"] = index
        item: dict[str, Any] = {}
        for field in section.fields:
            if not evaluate_condition(field.when, {**item_context, **item}):
                continue
            item[field.id] = resolve_field(field, {**item_context, **item}, None, assume_yes, console, repo_root)
        items.append(item)
    context[collection_key] = items


def write_resume_state(context: dict[str, Any]) -> Path:
    path = Path(context["wizard_resume_state_path"])
    ensure_private_dir(path.parent)
    atomic_write(path, yaml.safe_dump(context, sort_keys=False), 0o600)
    return path


def run_section_actions(
    section: SectionModel,
    context: dict[str, Any],
    repo_root: Path,
    assume_yes: bool,
    console: Console,
) -> None:
    for action in section.actions:
        if not evaluate_condition(action.when, context):
            continue

        if assume_yes:
            continue

        message = render_template_string(action.message_template, context)
        console.print(f"[yellow][bold]{section.title}[/bold][/yellow]")
        console.print(message)

        choice = questionary.select(
            action.prompt,
            choices=["Continue now", "Exit and resume later"],
            default="Continue now",
        ).ask()
        if choice == "Exit and resume later":
            resume_state_path = ""
            if action.save_state:
                resume_state_path = str(write_resume_state(context))
                context["resume_state_path"] = resume_state_path
            if resume_state_path:
                console.print(
                    f"[yellow]Resume later with:[/yellow] [bold]--answers-file {resume_state_path}[/bold]"
                )
            raise WizardPaused("Wizard paused by operator.")


def yaml_value(value: Any) -> str:
    text = yaml.safe_dump(value, sort_keys=False, default_flow_style=True).strip()
    text = "\n".join(line for line in text.splitlines() if line not in {"---", "..."})
    return text if text != "..." else '""'


def yaml_block(value: Any, indent: int = 0) -> str:
    text = yaml.safe_dump(value, sort_keys=False, default_flow_style=False).rstrip()
    text = "\n".join(line for line in text.splitlines() if line not in {"---", "..."})
    lines = text.splitlines()
    if indent <= 0:
        return "\n".join(lines)
    prefix = " " * indent
    return "\n".join(prefix + line if line else line for line in lines)


def indent_text(value: Any, indent: int = 0) -> str:
    text = str(value).strip("\n")
    lines = text.splitlines() or [""]
    prefix = " " * indent
    return "\n".join(prefix + line if line else prefix for line in lines)


def display_path(path: Path, repo_root: Path) -> str:
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return str(path)


def build_environment(template_root: Path) -> Environment:
    environment = Environment(
        loader=FileSystemLoader(str(template_root)),
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    environment.filters["yaml_value"] = yaml_value
    environment.filters["yaml_block"] = yaml_block
    environment.filters["indent_text"] = indent_text
    return environment


def render_outputs(profile: ProfileModel, context: dict[str, Any], template_root: Path) -> list[tuple[OutputModel, str]]:
    environment = build_environment(template_root)
    rendered: list[tuple[OutputModel, str]] = []
    for output in profile.outputs:
        if not evaluate_condition(output.when, context):
            continue
        template = environment.get_template(output.template)
        rendered.append((output, template.render(**context)))
    return rendered


def sanitize_for_log(context: dict[str, Any]) -> dict[str, Any]:
    sanitized = {
        "host_name": context.get("host_name"),
        "base_domain": context.get("base_domain"),
        "ops_domain": context.get("ops_domain"),
        "feature_obsidian_enabled": context.get("feature_obsidian_enabled"),
        "restic_enabled": context.get("restic_enabled"),
        "tailscale_hostname": context.get("tailscale_hostname"),
        "generated_secret_fingerprints": context.get("generated_secret_fingerprints", []),
        "generated_ssh_public_keys": context.get("generated_ssh_public_keys", []),
        "vault_reference_summary": context.get("vault_reference_summary", []),
    }
    return sanitized


def write_audit_log(repo_root: Path, context: dict[str, Any]) -> Path:
    path = Path(context["wizard_run_dir"]) / "config-wizard-audit.json"
    ensure_private_dir(path.parent)
    payload = {
        "generated_at": context["timestamp"],
        "profile": context["profile_id"],
        "summary": sanitize_for_log(context),
    }
    atomic_write(path, json.dumps(payload, indent=2) + "\n", 0o600)
    return path


def cleanup_generated_resume_state(answers_path: Path | None, context: dict[str, Any], console: Console) -> None:
    if answers_path is None:
        return
    resolved_answers = answers_path.resolve()
    wizard_state_dir = Path(context["wizard_state_dir"])
    if resolved_answers.name != "config-wizard-state.yml":
        return
    if not resolved_answers.is_relative_to(wizard_state_dir):
        return
    secure_delete(resolved_answers)
    console.print(f"[cyan]Deleted[/cyan] {resolved_answers}")


def encrypt_vault_file(repo_root: Path, vault_password_file: str | None, console: Console) -> None:
    vault_path = repo_root / "inventories/prod/group_vars/vault.yml"
    command = ["ansible-vault", "encrypt", str(vault_path)]
    if vault_password_file:
        command.extend(["--vault-password-file", vault_password_file])
    console.print(f"[cyan]Encrypting[/cyan] {vault_path}")
    subprocess.run(command, check=True, cwd=repo_root)


def run_preflight(repo_root: Path, console: Console) -> None:
    console.print("[cyan]Running[/cyan] preflight validation")
    subprocess.run(
        ["ansible-playbook", "-i", "inventories/prod/hosts.yml", "playbooks/preflight.yml"],
        check=True,
        cwd=repo_root,
    )


def maybe_prompt_option(
    answers: dict[str, Any],
    key: str,
    prompt: str,
    default: bool,
    assume_yes: bool,
) -> bool:
    if key in answers:
        return bool(answers[key])
    if assume_yes:
        return default
    return bool(questionary.confirm(prompt, default=default).ask())


def run_wizard(
    profile_path: Path,
    repo_root: Path,
    answers_path: Path | None = None,
    assume_yes: bool = False,
    encrypt_override: bool | None = None,
    preflight_override: bool | None = None,
) -> None:
    console = Console()
    profile = load_profile(profile_path)
    template_root = profile_path.parent.parent
    builder = resolve_builder(profile.builder, repo_root=repo_root, profile_root=template_root)
    provided_answers = load_answers(answers_path)
    context: dict[str, Any] = copy.deepcopy(profile.defaults)
    context["profile_id"] = profile.id
    context["timestamp"] = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    context["repo_root"] = str(repo_root)
    state_home = default_state_home()
    context["wizard_state_home"] = str(state_home)
    context["wizard_state_dir"] = str(
        ensure_private_dir(state_home / slugify(profile.id) / slugify(repo_root.name))
    )
    context["wizard_ssh_dir"] = str(
        ensure_private_dir(default_ssh_home() / slugify(repo_root.name))
    )
    context["wizard_run_dir"] = str(
        ensure_private_dir(Path(context["wizard_state_dir"]) / "runs" / context["timestamp"])
    )
    context["wizard_resume_state_path"] = str(Path(context["wizard_run_dir"]) / "config-wizard-state.yml")

    console.print(Panel.fit(f"{profile.name}\nProfile: {profile.id}", border_style="green"))

    for section in profile.sections:
        if not evaluate_condition(section.when, context):
            continue
        console.print(Panel.fit(section.title, border_style="blue"))
        if section.description:
            console.print(f"[dim]{section.description}[/dim]")
        if section.kind == "fields":
            collect_fields(section, context, provided_answers, assume_yes, console, repo_root)
        else:
            collect_repeatable(section, context, provided_answers, assume_yes, console, repo_root)
        run_section_actions(section, context, repo_root, assume_yes, console)

    write_details = maybe_prompt_option(provided_answers, "write_details", "Write sensitive details file?", False, assume_yes)
    include_secret_details = False
    if write_details:
        include_secret_details = maybe_prompt_option(
            provided_answers,
            "include_secret_details",
            "Include raw secret values in the details file?",
            False,
            assume_yes,
        )
    write_log = maybe_prompt_option(provided_answers, "write_log", "Write sanitized audit log?", False, assume_yes)

    context["write_details"] = write_details
    context["include_secret_details"] = include_secret_details

    built = builder(context)
    built["profile_id"] = context["profile_id"]
    built["timestamp"] = context["timestamp"]
    built["write_details"] = write_details
    built["include_secret_details"] = include_secret_details

    rendered_outputs = render_outputs(profile, built, template_root)
    for output, _ in rendered_outputs:
        backup_existing(repo_root / render_template_string(output.path, built))

    for output, content in rendered_outputs:
        target_path = repo_root / render_template_string(output.path, built)
        atomic_write(target_path, content.rstrip() + "\n", int(output.mode, 8))
        console.print(f"[green]Wrote[/green] {display_path(target_path, repo_root)}")

    log_path = None
    if write_log:
        log_path = write_audit_log(repo_root, built)
        console.print(f"[green]Wrote[/green] {display_path(log_path, repo_root)}")

    encrypt_vault = encrypt_override if encrypt_override is not None else maybe_prompt_option(
        provided_answers,
        "encrypt_vault",
        "Encrypt inventories/prod/group_vars/vault.yml now?",
        True,
        assume_yes,
    )
    if encrypt_vault:
        vault_password_file = provided_answers.get("vault_password_file")
        encrypt_vault_file(repo_root, vault_password_file, console)

    run_preflight_now = preflight_override if preflight_override is not None else maybe_prompt_option(
        provided_answers,
        "run_preflight",
        "Run preflight now?",
        False,
        assume_yes,
    )
    if run_preflight_now:
        run_preflight(repo_root, console)

    cleanup_generated_resume_state(answers_path, built, console)

    console.print(Panel.fit("Configuration wizard complete.", border_style="green"))
    if write_details:
        console.print("[yellow]Sensitive details file written. Store it carefully or delete it after handoff.[/yellow]")
    if log_path:
        console.print("[cyan]Sanitized audit log written.[/cyan]")
