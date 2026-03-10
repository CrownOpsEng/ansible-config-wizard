from __future__ import annotations

import ast
import copy
import json
import os
import re
import shlex
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic
from typing import Any

import pexpect
import questionary
import yaml
from jinja2 import Environment, FileSystemLoader
from prompt_toolkit.document import Document
from prompt_toolkit.key_binding import KeyBindings
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule

from .generators import generate_value, load_ed25519_keypair
from .models import ActionModel, FieldModel, OutputModel, ProfileModel, SectionModel
from .resolver import resolve_builder
from .writers import atomic_write, backup_existing, secure_delete


class WizardError(RuntimeError):
    pass


class WizardPaused(RuntimeError):
    pass


class RedactingConsoleWriter:
    def __init__(self, console: Console, secrets: list[str] | None = None) -> None:
        self.console = console
        self.secrets = [secret for secret in (secrets or []) if secret]

    def write(self, data: str) -> None:
        if not data:
            return
        rendered = data
        for secret in self.secrets:
            rendered = rendered.replace(secret, "[redacted]")
        self.console.print(rendered, end="", markup=False, highlight=False, soft_wrap=True)

    def flush(self) -> None:
        return


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


def is_generated_resume_state(path: Path | None, wizard_state_dir: Path) -> bool:
    if path is None:
        return False
    try:
        resolved = path.resolve()
    except FileNotFoundError:
        return False
    if resolved.name != "config-wizard-state.yml":
        return False
    try:
        resolved.relative_to(wizard_state_dir)
    except ValueError:
        return False
    return True


def latest_resume_state_path(wizard_state_dir: Path) -> Path | None:
    candidates = [
        path
        for path in wizard_state_dir.glob("runs/*/config-wizard-state.yml")
        if path.is_file()
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda path: path.stat().st_mtime)


def current_section_index(context: dict[str, Any]) -> int:
    return int(context.get("wizard_current_section_index", 0))


def furthest_resume_index(context: dict[str, Any]) -> int:
    return int(context.get("wizard_furthest_resume_index", context.get("wizard_resume_section_index", 0)))


def write_resume_state(context: dict[str, Any], section_index: int | None = None) -> Path:
    path = Path(context["wizard_resume_state_path"])
    ensure_private_dir(path.parent)
    snapshot = copy.deepcopy(context)
    snapshot["wizard_resume_enabled"] = True
    snapshot["wizard_resume_state"] = True
    snapshot["wizard_resume_section_index"] = current_section_index(context) if section_index is None else section_index
    snapshot["wizard_furthest_resume_index"] = max(
        int(snapshot["wizard_resume_section_index"]),
        int(snapshot.get("wizard_furthest_resume_index", 0)),
    )
    atomic_write(path, yaml.safe_dump(snapshot, sort_keys=False), 0o600)
    return path


def persist_progress(context: dict[str, Any], section_index: int | None = None) -> Path | None:
    if not context.get("wizard_resume_enabled"):
        return None
    if section_index is not None:
        context["wizard_resume_section_index"] = section_index
        context["wizard_furthest_resume_index"] = max(section_index, furthest_resume_index(context))
    return write_resume_state(context, section_index)


def exit_on_interrupt(context: dict[str, Any], console: Console) -> None:
    resume_state_path = persist_progress(context)
    console.print()
    if resume_state_path is not None:
        console.print(f"[yellow]Progress saved to:[/yellow] [bold]{resume_state_path}[/bold]")
        console.print(f"[yellow]Resume later with:[/yellow] [bold]--answers-file {resume_state_path}[/bold]")
    raise WizardPaused("Wizard interrupted by operator.")


def handle_prompt_interrupt(context: dict[str, Any], console: Console) -> None:
    interrupted_at = monotonic()
    last_interrupt = float(context.get("wizard_last_interrupt_at", 0.0))
    if interrupted_at - last_interrupt <= 2.5:
        exit_on_interrupt(context, console)
    resume_state_path = persist_progress(context)
    console.print()
    if resume_state_path is not None:
        console.print(f"[yellow]Progress saved to:[/yellow] [bold]{resume_state_path}[/bold]")
    console.print("[yellow]Press Ctrl-C again to exit, or continue with this step.[/yellow]")
    context["wizard_last_interrupt_at"] = interrupted_at


def ask_question(prompt: Any, context: dict[str, Any], console: Console) -> Any:
    while True:
        try:
            value = prompt.ask()
        except KeyboardInterrupt:
            handle_prompt_interrupt(context, console)
            continue
        if value is None:
            handle_prompt_interrupt(context, console)
            continue
        context["wizard_last_interrupt_at"] = 0.0
        return value


def evaluate_ast_expression(node: ast.AST, context: dict[str, Any]) -> Any:
    if isinstance(node, ast.Expression):
        return evaluate_ast_expression(node.body, context)
    if isinstance(node, ast.Name):
        return context.get(node.id)
    if isinstance(node, ast.Attribute):
        base = evaluate_ast_expression(node.value, context)
        if isinstance(base, dict):
            return base.get(node.attr)
        return getattr(base, node.attr, None)
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


def prompt_key_value(field: FieldModel, default: dict[str, str] | None, console: Console, context: dict[str, Any]) -> dict[str, str]:
    default = copy.deepcopy(default or {})
    console.print()
    if default:
        use_default = ask_question(
            questionary.confirm(
                f"{field.label}: keep existing/default key-value entries?",
                default=True,
            ),
            context,
            console,
        )
        if use_default:
            return default

    result: dict[str, str] = {}
    console.print(f"[bold]{field.label}[/bold]", style="cyan")
    console.print("Leave the key blank when you are finished.", style="dim")
    while True:
        key = ask_question(questionary.text("Key"), context, console)
        if not key:
            break
        value = (
            ask_question(questionary.password("Value"), context, console)
            if field.secret
            else ask_question(questionary.text("Value"), context, console)
        )
        result[key] = value or ""
    return result


def build_restore_default_bindings(default_value: str) -> KeyBindings:
    bindings = KeyBindings()

    @bindings.add("escape")
    def restore_default(event) -> None:
        event.app.current_buffer.set_document(Document(default_value, cursor_position=len(default_value)))

    return bindings


def text_like_question(
    field_type: str,
    prompt: str,
    default_value: str,
    restore_value: str,
):
    kwargs = {"key_bindings": build_restore_default_bindings(restore_value)}
    if field_type == "password":
        return questionary.password(prompt, default=default_value, **kwargs)
    if field_type == "multiline_text":
        return questionary.text(prompt, default=default_value, multiline=True, **kwargs)
    return questionary.text(prompt, default=default_value, **kwargs)


def prompt_field(
    field: FieldModel,
    display_default: Any,
    prompt_default: Any,
    console: Console,
    context: dict[str, Any],
) -> Any:
    console.print()
    prompt = field.label
    if field.help:
        console.print(field.help, style="dim")
    if field.type == "multiline_text":
        console.print("Paste one line per entry. Press Esc to restore the default buffer.", style="dim")
    if display_default not in (None, "", [], {}) and field.type not in {"confirm", "password", "ssh_keypair"}:
        console.print(f"Default: {display_default}", style="dim")
    if field.type == "confirm":
        console.print(f"Default: {'yes' if bool(display_default) else 'no'}", style="dim")

    if field.type == "confirm":
        value = ask_question(questionary.confirm(prompt, default=bool(prompt_default)), context, console)
        console.print()
        return value
    if field.type == "select":
        value = ask_question(questionary.select(prompt, choices=field.choices, default=prompt_default), context, console)
        console.print()
        return value
    if field.type == "password":
        value = ask_question(
            text_like_question(
                field.type,
                prompt,
                str(prompt_default or ""),
                str(display_default or ""),
            ),
            context,
            console,
        )
        console.print()
        return value
    if field.type == "multiline_text":
        value = ask_question(
            text_like_question(
                field.type,
                prompt,
                "" if prompt_default is None else str(prompt_default),
                "" if display_default is None else str(display_default),
            ),
            context,
            console,
        )
        console.print()
        return value
    if field.type == "int":
        value = int(
            ask_question(
                text_like_question(
                    "text",
                    prompt,
                    str(prompt_default or 0),
                    str(display_default or 0),
                ),
                context,
                console,
            )
        )
        console.print()
        return value
    if field.type == "list":
        prompt_default_text = ", ".join(prompt_default or [])
        display_default_text = ", ".join(display_default or [])
        answer = ask_question(
            text_like_question("text", prompt, prompt_default_text, display_default_text),
            context,
            console,
        )
        console.print()
        return normalize_value(field, answer)
    if field.type == "key_value":
        return prompt_key_value(field, prompt_default, console, context)
    if field.type == "ssh_keypair":
        return prompt_default
    value = ask_question(
        text_like_question(
            "text",
            prompt,
            "" if prompt_default is None else str(prompt_default),
            "" if display_default is None else str(display_default),
        ),
        context,
        console,
    )
    console.print()
    return value


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
    current_value: Any,
    assume_yes: bool,
    console: Console,
    repo_root: Path,
) -> Any:
    display_default = default_for_field(field, context)
    prompt_default = copy.deepcopy(current_value) if current_value is not None else copy.deepcopy(display_default)
    if current_value is None and provided_value is not None and not assume_yes:
        prompt_default = normalize_value(field, copy.deepcopy(provided_value))

    source = field.source
    if source.kind == "generate" and current_value is not None:
        return normalize_value(field, copy.deepcopy(current_value))
    if provided_value is not None and (assume_yes or source.kind == "generate"):
        return normalize_value(field, copy.deepcopy(provided_value))

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
        driver = ask_question(
            questionary.select(
                f"{field.label}: external vault driver",
                choices=["bitwarden", "1password", "vaultwarden", "aws_secrets_manager", "gcp_secret_manager", "hashicorp_vault"],
                default="bitwarden",
            ),
            context,
            console,
        )
        reference = ask_question(questionary.text(f"{field.label}: secret reference or ID"), context, console)
        return {"driver": driver, "ref": {"id": reference or ""}}

    if assume_yes:
        if prompt_default not in (None, "", [], {}):
            return normalize_value(field, prompt_default)
        if source.kind == "optional_prompt":
            return normalize_value(field, prompt_default)
        if field.required:
            raise WizardError(f"Missing value for required field: {field.id}")
        return normalize_value(field, prompt_default)

    value = prompt_field(field, display_default, prompt_default, console, context)
    if field.required and value in (None, "", [], {}):
        raise WizardError(f"Value required for field: {field.id}")
    return normalize_value(field, value)


def collect_fields(
    section: SectionModel,
    context: dict[str, Any],
    answers: dict[str, Any],
    assume_yes: bool,
    console: Console,
    repo_root: Path,
    answered_fields: set[str],
) -> None:
    for field in section.fields:
        if not evaluate_condition(field.when, context):
            continue
        provided = answers.get(field.id) if field.id in answers else None
        current_value = copy.deepcopy(context.get(field.id)) if field.id in context else None
        value = resolve_field(field, context, provided, current_value, assume_yes, console, repo_root)
        context[field.id] = value
        answered_fields.add(field.id)


def collect_repeatable(
    section: SectionModel,
    context: dict[str, Any],
    answers: dict[str, Any],
    assume_yes: bool,
    console: Console,
    repo_root: Path,
    answered_collections: set[str],
) -> None:
    collection_key = section.collection_key or section.id
    existing_items = copy.deepcopy(context.get(collection_key, []))
    provided_items = answers.get(collection_key) if collection_key in answers else None
    items: list[dict[str, Any]] = []

    if assume_yes and provided_items is not None:
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
                    None,
                    assume_yes,
                    console,
                    repo_root,
                )
            items.append(item)
        context[collection_key] = items
        answered_collections.add(collection_key)
        return

    if assume_yes and section.default_count == 0 and section.min_items == 0:
        context[collection_key] = []
        answered_collections.add(collection_key)
        return

    seed_items = copy.deepcopy(existing_items)
    if provided_items is not None:
        max_seed_len = max(len(seed_items), len(provided_items))
        while len(seed_items) < max_seed_len:
            seed_items.append({})
        for index, provided_item in enumerate(provided_items):
            if index >= len(seed_items):
                seed_items.append(copy.deepcopy(provided_item))
                continue
            merged = copy.deepcopy(provided_item)
            merged.update(seed_items[index])
            seed_items[index] = merged

    if not assume_yes:
        console.print(
            "We'll set these up one at a time so the values stay easy to reason about.",
            style="dim",
        )

    def prompt_repeatable_item(index: int, existing_item: dict[str, Any] | None = None) -> dict[str, Any]:
        console.print(
            Panel.fit(
                f"{section.item_label.title()} {index}",
                border_style="cyan",
                box=box.ROUNDED,
            )
        )
        item_context = copy.deepcopy(context)
        item_context["item_index"] = index
        item: dict[str, Any] = {}
        existing_item = existing_item or {}
        provided_item = (
            provided_items[index - 1]
            if provided_items is not None and index - 1 < len(provided_items)
            else {}
        )
        for field in section.fields:
            if not evaluate_condition(field.when, {**item_context, **item}):
                continue
            provided = copy.deepcopy(provided_item.get(field.id)) if field.id in provided_item else None
            current_value = copy.deepcopy(existing_item.get(field.id)) if field.id in existing_item else None
            item[field.id] = resolve_field(
                field,
                {**item_context, **item},
                provided,
                current_value,
                assume_yes,
                console,
                repo_root,
            )
        return item

    existing_limit = len(seed_items)
    if seed_items and not assume_yes and section.min_items == 0:
        console.print(
            f"You already have {len(seed_items)} saved {section.item_label} entr{'y' if len(seed_items) == 1 else 'ies'}.",
            style="dim",
        )
        keep_existing = ask_question(
            questionary.confirm(
                f"Start by reviewing those existing {section.item_label} entries?",
                default=True,
            ),
            context,
            console,
        )
        console.print()
        if not keep_existing:
            existing_limit = 0

    for index in range(1, existing_limit + 1):
        existing_item = seed_items[index - 1]
        items.append(prompt_repeatable_item(index, existing_item))
        remaining_existing = existing_limit - index
        required_remaining = max(section.min_items - len(items), 0)
        if remaining_existing > 0 and required_remaining == 0 and not assume_yes:
            console.print()
            review_next = ask_question(
                questionary.confirm(
                    f"Keep another existing {section.item_label}?",
                    default=True,
                ),
                context,
                console,
            )
            console.print()
            if not review_next:
                break

    required_count = section.min_items if seed_items else max(section.min_items, section.default_count)
    next_index = len(items) + 1
    while len(items) < required_count:
        items.append(prompt_repeatable_item(next_index))
        next_index += 1
    while not assume_yes:
        console.print()
        add_another = ask_question(
            questionary.confirm(
                f"Add another {section.item_label}?",
                default=False,
            ),
            context,
            console,
        )
        console.print()
        if not add_another:
            break
        items.append(prompt_repeatable_item(next_index))
        next_index += 1

    context[collection_key] = items
    answered_collections.add(collection_key)


def previous_visible_section_index(sections: list[SectionModel], context: dict[str, Any], current_index: int) -> int | None:
    for index in range(current_index - 1, -1, -1):
        if evaluate_condition(sections[index].when, context):
            return index
    return None


def completed_visible_sections(
    sections: list[SectionModel],
    context: dict[str, Any],
    current_index: int,
) -> list[tuple[int, int, SectionModel]]:
    completed: list[tuple[int, int, SectionModel]] = []
    step_number = 0
    for index, section in enumerate(sections):
        if not evaluate_condition(section.when, context):
            continue
        step_number += 1
        if index <= current_index:
            completed.append((index, step_number, section))
    return completed


def choose_completed_section(
    profile: ProfileModel,
    context: dict[str, Any],
    current_index: int,
    resume_index: int,
    console: Console,
) -> int | None:
    completed = completed_visible_sections(profile.sections, context, current_index)
    labels: list[str] = []
    label_to_index: dict[str, int] = {}
    if resume_index <= len(profile.sections):
        resume_label = f"Resume at {describe_step_target(profile, context, resume_index - 1)}"
        labels.append(resume_label)
        label_to_index[resume_label] = resume_index
    for index, step_number, section in completed:
        label = f"Review Step {step_number}: {section.title}"
        labels.append(label)
        label_to_index[label] = index
    if not labels:
        return None

    console.print()
    choice = ask_question(
        questionary.select(
            "Pick a step to revisit, or jump back to your furthest saved point.",
            choices=labels,
            default=labels[0],
        ),
        context,
        console,
    )
    console.print()
    return label_to_index[choice]


def describe_next_step(profile: ProfileModel, context: dict[str, Any], current_index: int) -> str:
    for index in range(current_index + 1, len(profile.sections)):
        section = profile.sections[index]
        if evaluate_condition(section.when, context):
            step_number = sum(
                1 for item in profile.sections[: index + 1] if evaluate_condition(item.when, context)
            )
            return f"Continue to Step {step_number}: {section.title}"
    return "Continue to final output options"


def describe_step_target(profile: ProfileModel, context: dict[str, Any], current_index: int) -> str:
    label = describe_next_step(profile, context, current_index)
    if label.startswith("Continue to "):
        return label.removeprefix("Continue to ")
    return "final output options"


def choose_resume_section(
    profile: ProfileModel,
    context: dict[str, Any],
    resume_index: int,
    console: Console,
) -> int:
    completed = completed_visible_sections(profile.sections, context, resume_index - 1)
    choices: list[str] = []
    label_to_index: dict[str, int] = {}

    continue_label = f"Resume at {describe_step_target(profile, context, resume_index - 1)}"
    choices.append(continue_label)
    label_to_index[continue_label] = resume_index

    for index, step_number, section in completed:
        label = f"Review Step {step_number}: {section.title}"
        choices.append(label)
        label_to_index[label] = index

    console.print()
    console.print("[bold]Resume point[/bold]", style="cyan")
    console.print(
        "Continue from your furthest saved point, or reopen any finished step with your current answers prefilled.",
        style="dim",
    )
    console.print()
    selection = ask_question(
        questionary.select(
            "Where do you want to begin?",
            choices=choices,
            default=continue_label,
        ),
        context,
        console,
    )
    console.print()
    return label_to_index[selection]


def next_navigation_choices(profile: ProfileModel, context: dict[str, Any], current_index: int) -> list[str]:
    choices: list[str] = []
    direct_next = describe_next_step(profile, context, current_index)
    choices.append(direct_next)

    resume_index = furthest_resume_index(context)
    resume_label = f"Resume at {describe_step_target(profile, context, resume_index - 1)}"
    if resume_index != current_index + 1 and resume_label != direct_next:
        choices.append(resume_label)

    if completed_visible_sections(profile.sections, context, resume_index - 1):
        choices.append("Review a step")
    return choices


def write_command_file(name: str, commands: str, context: dict[str, Any]) -> Path:
    path = Path(context["wizard_run_dir"]) / f"{slugify(name)}-commands.sh"
    script = "#!/usr/bin/env bash\nset -euo pipefail\n\n" + commands.strip() + "\n"
    atomic_write(path, script, 0o700)
    return path


def write_action_commands(section: SectionModel, commands: str, context: dict[str, Any]) -> Path:
    return write_command_file(section.id, commands, context)


def ssh_command_env() -> dict[str, str]:
    env = os.environ.copy()
    env.pop("SSH_AUTH_SOCK", None)
    return env


def quote_shell_value(value: str) -> str:
    escaped = value.replace("'", "'\"'\"'")
    return f"'{escaped}'"


def format_shell_command(parts: list[str]) -> str:
    if not parts:
        return ""
    remaining = list(parts)
    lines: list[str] = []

    if len(remaining) >= 3 and remaining[0] == "env" and remaining[1] == "-u":
        lines.append(f"env -u {remaining[2]} \\")
        remaining = remaining[3:]

    if not remaining:
        return "\n".join(lines).rstrip("\\").rstrip()

    lines.append(f"  {shlex.quote(remaining[0])} \\")
    remaining = remaining[1:]

    flags_with_values = {"-o", "-i", "-p", "-l", "-J", "-F"}
    index = 0
    while index < len(remaining):
        token = remaining[index]
        if token in flags_with_values and index + 1 < len(remaining):
            value = remaining[index + 1]
            lines.append(f"  {token} {quote_shell_value(value)} \\")
            index += 2
            continue
        if token.startswith("-"):
            lines.append(f"  {token} \\")
        else:
            lines.append(f"  {quote_shell_value(token)} \\")
        index += 1

    if lines:
        lines[-1] = lines[-1].removesuffix(" \\")
    return "\n".join(lines)


def build_ssh_setup_commands(host: str, ssh_user: str, public_key_path: str, private_key_path: str, resume_command: str) -> str:
    target = f"{ssh_user}@{host}"
    copy_id = format_shell_command(
        [
            "env",
            "-u",
            "SSH_AUTH_SOCK",
            "ssh-copy-id",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityAgent=none",
            "-o",
            "PreferredAuthentications=password",
            "-o",
            "PubkeyAuthentication=no",
            "-i",
            public_key_path,
            target,
        ]
    )
    verify = format_shell_command(
        [
            "env",
            "-u",
            "SSH_AUTH_SOCK",
            "ssh",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityAgent=none",
            "-i",
            private_key_path,
            target,
        ]
    )
    return "\n\n".join([copy_id, verify, resume_command.strip()])


def install_ssh_key_with_password(
    host: str,
    ssh_user: str,
    public_key_path: str,
    password: str,
    console: Console,
) -> None:
    command = [
        "ssh-copy-id",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "IdentityAgent=none",
        "-o",
        "PreferredAuthentications=password",
        "-o",
        "PubkeyAuthentication=no",
        "-i",
        public_key_path,
        f"{ssh_user}@{host}",
    ]
    console.print("[cyan]Running local SSH key install:[/cyan]")
    console.print(
        format_shell_command(["env", "-u", "SSH_AUTH_SOCK", *command]),
        markup=False,
        highlight=False,
        no_wrap=True,
        overflow="ignore",
    )
    console.print()
    child = pexpect.spawn(command[0], command[1:], env=ssh_command_env(), encoding="utf-8", timeout=30, echo=False)
    child.logfile_read = RedactingConsoleWriter(console, secrets=[password])
    password_prompts = 0
    output = ""
    try:
        while True:
            index = child.expect(
                [
                    r"Are you sure you want to continue connecting \(yes/no(?:/\[fingerprint\])?\)\?",
                    r"(?i)password:",
                    r"Too many authentication failures",
                    pexpect.EOF,
                    pexpect.TIMEOUT,
                ]
            )
            output += child.before
            if index == 0:
                child.sendline("yes")
                continue
            if index == 1:
                password_prompts += 1
                if password_prompts > 3:
                    raise WizardError("SSH password was rejected too many times while installing the managed key.")
                child.sendline(password)
                continue
            if index == 2:
                raise WizardError("SSH key install failed because the server rejected too many authentication attempts.")
            if index == 3:
                break
            raise WizardError("Timed out while waiting for ssh-copy-id to complete.")
    finally:
        child.close()

    console.print()

    if child.exitstatus != 0:
        raise WizardError(f"ssh-copy-id failed with exit code {child.exitstatus}: {output.strip() or 'no output'}")


def verify_ssh_key_access(host: str, ssh_user: str, private_key_path: str) -> None:
    command = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "IdentityAgent=none",
        "-i", private_key_path,
        f"{ssh_user}@{host}",
        "exit",
    ]
    result = subprocess.run(command, check=False, env=ssh_command_env(), capture_output=True, text=True)
    if result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip() or "no output"
        raise WizardError(f"Managed SSH key installed, but verification failed: {stderr}")


def render_manual_action_commands(
    action_name: str,
    commands: str,
    context: dict[str, Any],
    console: Console,
) -> None:
    command_path = write_command_file(action_name, commands, context)
    console.print()
    console.print("[cyan]Manual commands file[/cyan]")
    console.print(str(command_path), soft_wrap=True, highlight=False)
    console.print()
    console.print("[cyan]Manual commands[/cyan]")
    console.print(commands, markup=False, highlight=False, no_wrap=True, overflow="ignore")
    console.print()


def pause_wizard(action: ActionModel, context: dict[str, Any], console: Console) -> None:
    resume_state_path = ""
    if action.save_state or context.get("wizard_resume_enabled"):
        resume_state_path = str(write_resume_state(context))
        context["resume_state_path"] = resume_state_path
    if resume_state_path:
        console.print(f"[yellow]Resume later with:[/yellow] [bold]--answers-file {resume_state_path}[/bold]")
    raise WizardPaused("Wizard paused by operator.")


def run_ssh_setup_action(action: ActionModel, section: SectionModel, context: dict[str, Any], console: Console) -> None:
    host = render_template_string(action.host_template, context)
    ssh_user = render_template_string(action.ssh_user_template, context)
    public_key_path = render_template_string(action.public_key_path_template, context)
    private_key_path = render_template_string(action.private_key_path_template, context)
    resume_command = f"./scripts/configure.sh --answers-file {context['wizard_resume_state_path']}"
    commands = (
        render_template_string(action.commands_template, context).strip()
        if action.commands_template
        else build_ssh_setup_commands(host, ssh_user, public_key_path, private_key_path, resume_command)
    )
    login_command = format_shell_command(
        [
            "env",
            "-u",
            "SSH_AUTH_SOCK",
            "ssh",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityAgent=none",
            "-i",
            private_key_path,
            f"{ssh_user}@{host}",
        ]
    )
    manual_requested = False

    while True:
        message = render_template_string(action.message_template, context)
        console.print(Rule(f"[bold cyan]{section.title}[/bold cyan]"))
        console.print(message.strip(), soft_wrap=True, highlight=False)
        console.print()
        console.print(
            "Recommended: let the wizard install the key now. Manual commands stay available if you want them.",
            style="dim",
        )
        console.print()
        if manual_requested:
            render_manual_action_commands(section.id, commands, context, console)

        choice = ask_question(
            questionary.select(
                action.prompt,
                choices=[
                    "Install now (recommended)",
                    "Show manual steps",
                    "I already finished this, continue",
                    "Pause here and resume later",
                ],
                default="Install now (recommended)",
            ),
            context,
            console,
        )
        if choice == "Install now (recommended)":
            password = ask_question(questionary.password(f"Password for {ssh_user}@{host}"), context, console)
            if not password:
                console.print("[yellow]No password entered.[/yellow]")
                continue
            try:
                install_ssh_key_with_password(host, ssh_user, public_key_path, password, console)
                verify_ssh_key_access(host, ssh_user, private_key_path)
            except WizardError as exc:
                console.print(f"[red]{exc}[/red]")
                manual_requested = True
                follow_up = ask_question(
                    questionary.select(
                        "The automatic path hit a snag. What do you want to do next?",
                        choices=[
                            "Show manual steps",
                            "Try automatic install again",
                            "Pause here and resume later",
                        ],
                        default="Show manual steps",
                    ),
                    context,
                    console,
                )
                if follow_up == "Try automatic install again":
                    continue
                if follow_up == "Pause here and resume later":
                    pause_wizard(action, context, console)
                continue
            console.print("[green]Managed SSH key installed and verified.[/green]")
            console.print()
            console.print("[cyan]Direct login check[/cyan]")
            console.print(login_command, markup=False, highlight=False, no_wrap=True, overflow="ignore")
            console.print()
            return
        if choice == "Show manual steps":
            manual_requested = True
            continue
        if choice == "Pause here and resume later":
            pause_wizard(action, context, console)
        return


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

        if action.kind == "ssh_setup":
            run_ssh_setup_action(action, section, context, console)
            continue

        message = render_template_string(action.message_template, context)
        console.print(Rule(f"[bold cyan]{section.title}[/bold cyan]"))
        console.print(message, soft_wrap=True, highlight=False)

        if action.commands_template:
            commands = render_template_string(action.commands_template, context).strip()
            render_manual_action_commands(section.id, commands, context, console)

        choice = ask_question(
            questionary.select(
                action.prompt,
                choices=["Continue now", "Exit and resume later"],
                default="Continue now",
            ),
            context,
            console,
        )
        if choice == "Exit and resume later":
            pause_wizard(action, context, console)


def run_local_command(command: str, working_directory: Path | None, console: Console) -> None:
    console.print("[cyan]Running local command[/cyan]")
    console.print(command, markup=False, highlight=False, no_wrap=True, overflow="ignore")
    console.print()
    subprocess.run(
        shlex.split(command),
        check=True,
        cwd=str(working_directory) if working_directory is not None else None,
    )


LOCAL_COMMAND_LABELS = {
    "show": "Show command",
    "run": "Run now",
    "leave": "Leave for later",
}


def local_command_choice_labels(action: ActionModel) -> list[str]:
    return [LOCAL_COMMAND_LABELS[name] for name in action.available_choices]


def local_command_choice_default(action: ActionModel) -> str:
    return LOCAL_COMMAND_LABELS[action.default_choice]


def run_local_command_action(
    action: ActionModel,
    context: dict[str, Any],
    console: Console,
    action_item: Any | None = None,
) -> None:
    action_context = copy.deepcopy(context)
    action_context["action_item"] = action_item
    action_name = action.collection_key or action.kind
    if isinstance(action_item, dict) and action_item.get("name"):
        action_name = f"{action_name}-{action_item['name']}"
    message = render_template_string(action.message_template, action_context).strip()
    command = render_template_string(action.command_template, action_context).strip() if action.command_template else ""
    working_directory = None
    if action.working_directory_template:
        working_directory = Path(render_template_string(action.working_directory_template, action_context))
    command_path = write_command_file(action_name, command, action_context) if command else None

    show_manual = False
    while True:
        console.print(Rule("[bold cyan]Optional Setup[/bold cyan]"))
        console.print(message, soft_wrap=True, highlight=False)
        console.print()
        if command_path is not None:
            console.print(f"[cyan]Prepared command file[/cyan] {command_path}")
            console.print()
        console.print(
            "The wizard has prepared the next-step command. You can inspect it now, run it immediately, or leave it for later.",
            style="dim",
        )
        if show_manual and command:
            console.print()
            console.print("[cyan]Follow-up command[/cyan]")
            console.print(command, markup=False, highlight=False, no_wrap=True, overflow="ignore")
            console.print()

        choice = ask_question(
            questionary.select(
                action.prompt,
                choices=local_command_choice_labels(action),
                default=local_command_choice_default(action),
            ),
            context,
            console,
        )
        console.print()
        if choice == "Show command":
            show_manual = True
            continue
        if choice == "Leave for later":
            return
        try:
            run_local_command(command, working_directory, console)
        except subprocess.CalledProcessError as exc:
            console.print(f"[red]Command failed with exit code {exc.returncode}.[/red]")
            show_manual = True
            follow_up = ask_question(
                questionary.select(
                    "What do you want to do next?",
                    choices=[
                        "Show command",
                        "Try again",
                        "Leave for later",
                    ],
                    default="Show command",
                ),
                context,
                console,
            )
            console.print()
            if follow_up == "Try again":
                continue
            if follow_up == "Leave for later":
                return
            continue
        return


def run_post_write_actions(
    profile: ProfileModel,
    context: dict[str, Any],
    repo_root: Path,
    assume_yes: bool,
    console: Console,
) -> None:
    if assume_yes:
        return
    for action in profile.post_write_actions:
        if action.kind != "local_command":
            continue
        items = [None]
        if action.collection_key:
            items = context.get(action.collection_key, []) or []
        for action_item in items:
            action_context = copy.deepcopy(context)
            action_context["action_item"] = action_item
            if not evaluate_condition(action.when, action_context):
                continue
            run_local_command_action(action, context, console, action_item)


def render_welcome(console: Console, profile: ProfileModel, assume_yes: bool) -> None:
    mode_label = "guided" if not assume_yes else "non-interactive"
    console.print(
        Panel(
            f"[bold green]{profile.name}[/bold green]\n"
            f"[dim]Profile: {profile.id}[/dim]\n\n"
            "A calm setup pass with secure defaults, clear branches, and a clean handoff at the end.\n"
            f"[dim]Mode: {mode_label}[/dim]",
            border_style="green",
            box=box.ROUNDED,
            padding=(1, 2),
        )
    )


def render_startup_intro(console: Console) -> None:
    console.print()
    console.print("[bold cyan]Startup choices[/bold cyan]")
    console.print(
        "A few top-level preferences shape the rest of the run before the numbered steps begin.",
        style="dim",
    )


def render_section_intro(console: Console, section: SectionModel, index: int) -> None:
    body = ""
    if section.description:
        body = f"{section.description}\n\n"
    body += f"[dim]Step {index}[/dim]"
    console.print(
        Panel(
            body,
            title=f"[bold blue]{section.title}[/bold blue]",
            border_style="blue",
            box=box.ROUNDED,
            padding=(0, 2),
        )
    )


def render_review_summary(console: Console, built: dict[str, Any], rendered_outputs: list[tuple[OutputModel, str]], repo_root: Path) -> None:
    summary_lines = [
        f"Host: {built.get('host_name', 'unset')}",
        f"Primary address: {built.get('ansible_host', 'unset')}",
        f"SSH user: {built.get('ansible_user', 'unset')}",
    ]
    if built.get("feature_obsidian_enabled"):
        summary_lines.append(
            f"Obsidian: enabled via {built.get('obsidian_access_mode', 'unset')}"
        )
    else:
        summary_lines.append("Obsidian: disabled")
    if built.get("restic_enabled"):
        summary_lines.append(
            f"Backups: enabled with {len(built.get('restic_targets', []))} target(s)"
        )
    else:
        summary_lines.append("Backups: disabled")
    summary_lines.append(f"Outputs: {', '.join(display_path(repo_root / render_template_string(output.path, built), repo_root) for output, _ in rendered_outputs)}")
    console.print(
        Panel(
            "\n".join(summary_lines) + "\n\n[dim]Next, the wizard will write files and offer the optional safety steps.[/dim]",
            title="[bold magenta]Review[/bold magenta]",
            border_style="magenta",
            box=box.ROUNDED,
            padding=(0, 2),
        )
    )


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
    wizard_state_dir = Path(context["wizard_state_dir"])
    candidates: set[Path] = set()
    if answers_path is not None and is_generated_resume_state(answers_path, wizard_state_dir):
        candidates.add(answers_path.resolve())
    current_resume = Path(context["wizard_resume_state_path"])
    if current_resume.exists() and is_generated_resume_state(current_resume, wizard_state_dir):
        candidates.add(current_resume.resolve())
    for candidate in sorted(candidates):
        secure_delete(candidate)
        console.print(f"[cyan]Deleted[/cyan] {candidate}")


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
    context: dict[str, Any],
    console: Console,
) -> bool:
    if key in answers:
        return bool(answers[key])
    if assume_yes:
        return default
    return bool(ask_question(questionary.confirm(prompt, default=default), context, console))


def explain_next_choice(console: Console, title: str, body: str) -> None:
    console.print(f"[bold]{title}[/bold]", style="cyan")
    console.print(body, style="dim")


def choose_startup_answers_path(
    explicit_answers_path: Path | None,
    context: dict[str, Any],
    assume_yes: bool,
    console: Console,
) -> tuple[Path | None, bool]:
    wizard_state_dir = Path(context["wizard_state_dir"])
    if explicit_answers_path is not None:
        return explicit_answers_path, is_generated_resume_state(explicit_answers_path, wizard_state_dir)
    if assume_yes:
        return None, False

    latest_resume = latest_resume_state_path(wizard_state_dir)
    if latest_resume is None:
        return None, False

    console.print()
    console.print("[bold]Previous run found[/bold]", style="cyan")
    console.print(
        f"A saved wizard run is available at {latest_resume}. You can resume it or start fresh.",
        style="dim",
    )
    console.print()
    choice = ask_question(
        questionary.select(
            "How do you want to start?",
            choices=[
                "Resume the last run",
                "Start fresh",
            ],
            default="Resume the last run",
        ),
        context,
        console,
    )
    console.print()
    if choice == "Resume the last run":
        return latest_resume, True
    return None, False


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
    context: dict[str, Any] = copy.deepcopy(profile.defaults)
    context["profile_id"] = profile.id
    context["timestamp"] = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    context["repo_root"] = str(repo_root)
    context["wizard_last_interrupt_at"] = 0.0
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
    selected_answers_path, is_resume_state = choose_startup_answers_path(answers_path, context, assume_yes, console)
    loaded_answers = load_answers(selected_answers_path)
    if is_resume_state:
        context.update(loaded_answers)
        provided_answers: dict[str, Any] = {}
    else:
        provided_answers = loaded_answers
    if "wizard_last_interrupt_at" not in context:
        context["wizard_last_interrupt_at"] = 0.0
    if "wizard_resume_section_index" not in context:
        context["wizard_resume_section_index"] = 0
    if "wizard_furthest_resume_index" not in context:
        context["wizard_furthest_resume_index"] = int(context["wizard_resume_section_index"])
    if assume_yes:
        context["wizard_resume_enabled"] = bool(context.get("wizard_resume_enabled", False))
    elif is_resume_state:
        context["wizard_resume_enabled"] = True
    else:
        console.print()
        explain_next_choice(
            console,
            "Resumable run",
            "The wizard can save progress after each section so you can safely pause, recover from interrupts, or pick up later without retyping everything.",
        )
        context["wizard_resume_enabled"] = bool(
            ask_question(
                questionary.confirm("Keep this run resumable while you work?", default=True),
                context,
                console,
            )
        )
        console.print()
    answered_fields: set[str] = set()
    answered_collections: set[str] = set()

    render_welcome(console, profile, assume_yes)
    if profile.startup_fields:
        render_startup_intro(console)
        startup_section = SectionModel(id="startup", title="Startup", fields=profile.startup_fields)
        collect_fields(startup_section, context, provided_answers, assume_yes, console, repo_root, answered_fields)
        persist_progress(context, 0)

    section_index = int(context.get("wizard_resume_section_index", 0))
    if is_resume_state and not assume_yes and furthest_resume_index(context) <= len(profile.sections):
        section_index = choose_resume_section(profile, context, furthest_resume_index(context), console)
    while section_index < len(profile.sections):
        context["wizard_current_section_index"] = section_index
        context["wizard_resume_section_index"] = section_index
        section = profile.sections[section_index]
        if not evaluate_condition(section.when, context):
            section_index += 1
            continue

        step_index = sum(1 for item in profile.sections[: section_index + 1] if evaluate_condition(item.when, context))
        render_section_intro(console, section, step_index)
        if section.kind == "fields":
            collect_fields(section, context, provided_answers, assume_yes, console, repo_root, answered_fields)
        else:
            collect_repeatable(
                section,
                context,
                provided_answers,
                assume_yes,
                console,
                repo_root,
                answered_collections,
            )
        run_section_actions(section, context, repo_root, assume_yes, console)

        persist_progress(context, section_index + 1)

        if assume_yes:
            section_index += 1
            continue

        nav_choices = next_navigation_choices(profile, context, section_index)
        console.print(
            "Continue moves to the next step from here. Resume jumps back to the furthest point you had already reached.",
            style="dim",
        )
        console.print()
        navigation = ask_question(
            questionary.select(
                "What do you want to do next?",
                choices=nav_choices,
                default=nav_choices[0],
            ),
            context,
            console,
        )
        console.print()
        if navigation == "Review a step":
            resume_index = furthest_resume_index(context)
            previous_index = choose_completed_section(profile, context, resume_index - 1, resume_index, console)
            if previous_index is not None:
                section_index = previous_index
                continue
        if navigation.startswith("Resume at "):
            section_index = furthest_resume_index(context)
            continue
        section_index += 1

    explain_next_choice(
        console,
        "Optional record file",
        "A private details file can capture setup notes and, if you choose, raw secrets for handoff or safekeeping.",
    )
    write_details = maybe_prompt_option(
        provided_answers,
        "write_details",
        "Write sensitive details file?",
        False,
        assume_yes,
        context,
        console,
    )
    include_secret_details = False
    if write_details:
        explain_next_choice(
            console,
            "Raw secrets in the record file",
            "Including raw secrets makes handoff easier, but it also creates another sensitive file to protect or delete afterward.",
        )
        include_secret_details = maybe_prompt_option(
            provided_answers,
            "include_secret_details",
            "Include raw secret values in the details file?",
            False,
            assume_yes,
            context,
            console,
        )
    explain_next_choice(
        console,
        "Optional audit log",
        "The audit log records what the wizard did without storing raw secrets. It is useful for traceability and reruns.",
    )
    write_log = maybe_prompt_option(
        provided_answers,
        "write_log",
        "Write sanitized audit log?",
        False,
        assume_yes,
        context,
        console,
    )

    context["write_details"] = write_details
    context["include_secret_details"] = include_secret_details

    built = builder(context)
    built["profile_id"] = context["profile_id"]
    built["timestamp"] = context["timestamp"]
    built["write_details"] = write_details
    built["include_secret_details"] = include_secret_details

    rendered_outputs = render_outputs(profile, built, template_root)
    render_review_summary(console, built, rendered_outputs, repo_root)
    for output, _ in rendered_outputs:
        backup_existing(repo_root / render_template_string(output.path, built))

    for output, content in rendered_outputs:
        target_path = repo_root / render_template_string(output.path, built)
        atomic_write(target_path, content.rstrip() + "\n", int(output.mode, 8))
        console.print(f"[green]Wrote[/green] {display_path(target_path, repo_root)}")

    run_post_write_actions(profile, built, repo_root, assume_yes, console)

    log_path = None
    if write_log:
        log_path = write_audit_log(repo_root, built)
        console.print(f"[green]Wrote[/green] {display_path(log_path, repo_root)}")

    explain_next_choice(
        console,
        "Vault encryption",
        "If you encrypt vault.yml now, the secret file is protected before any real deployment steps begin.",
    )
    encrypt_vault = encrypt_override if encrypt_override is not None else maybe_prompt_option(
        provided_answers,
        "encrypt_vault",
        "Encrypt inventories/prod/group_vars/vault.yml now?",
        True,
        assume_yes,
        context,
        console,
    )
    if encrypt_vault:
        vault_password_file = provided_answers.get("vault_password_file")
        encrypt_vault_file(repo_root, vault_password_file, console)

    explain_next_choice(
        console,
        "Preflight validation",
        "Preflight checks the generated inventory for missing values, risky combinations, and obvious deployment blockers before you touch the host.",
    )
    run_preflight_now = preflight_override if preflight_override is not None else maybe_prompt_option(
        provided_answers,
        "run_preflight",
        "Run preflight now?",
        False,
        assume_yes,
        context,
        console,
    )
    if run_preflight_now:
        run_preflight(repo_root, console)

    cleanup_generated_resume_state(selected_answers_path, built, console)

    console.print(
        Panel(
            "[bold green]Configuration complete.[/bold green]\n"
            "[dim]Your files are written and the next deployment steps are ready when you are.[/dim]",
            border_style="green",
            box=box.ROUNDED,
            padding=(1, 2),
        )
    )
    if write_details:
        console.print("[yellow]Sensitive details file written. Store it carefully or delete it after handoff.[/yellow]")
    if log_path:
        console.print("[cyan]Sanitized audit log written.[/cyan]")
