from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


class SourceModel(BaseModel):
    kind: Literal["prompt", "generate", "optional_prompt", "external_vault", "known_hosts_scan"] = "prompt"
    generator: str | None = None
    driver: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)


class FieldModel(BaseModel):
    id: str
    label: str
    type: Literal["text", "multiline_text", "password", "confirm", "select", "list", "key_value", "int", "ssh_keypair"] = "text"
    help: str | None = None
    required: bool = False
    secret: bool = False
    when: str | None = None
    default: Any = None
    default_template: str | None = None
    choices: list[str] = Field(default_factory=list)
    separator: str = ","
    source: SourceModel = Field(default_factory=SourceModel)


class LocalCommandOptionModel(BaseModel):
    id: str
    label: str
    command_template: str
    description: str | None = None
    when: str | None = None
    working_directory_template: str | None = None


class ActionModel(BaseModel):
    kind: Literal["pause", "ssh_setup", "local_command"] = "pause"
    when: str | None = None
    message_template: str
    commands_template: str | None = None
    command_template: str | None = None
    command_options: list[LocalCommandOptionModel] = Field(default_factory=list)
    prompt: str = "Continue after completing this step?"
    available_choices: list[Literal["show", "run", "leave"]] = Field(
        default_factory=lambda: ["show", "run", "leave"]
    )
    default_choice: Literal["show", "run", "leave"] = "show"
    write_command_file: bool = False
    save_state: bool = False
    collection_key: str | None = None
    working_directory_template: str | None = None
    host_template: str | None = None
    ssh_user_template: str | None = None
    public_key_path_template: str | None = None
    private_key_path_template: str | None = None

    @model_validator(mode="after")
    def validate_action(self) -> "ActionModel":
        if self.kind == "local_command":
            has_single_command = bool(self.command_template)
            has_command_options = bool(self.command_options)
            if has_single_command == has_command_options:
                raise ValueError(
                    "local_command actions require exactly one of command_template or command_options"
                )
        if not self.available_choices:
            raise ValueError("available_choices must not be empty")
        if self.default_choice not in self.available_choices:
            raise ValueError("default_choice must be included in available_choices")
        return self


class RepeatableModel(BaseModel):
    id: str
    title: str
    description: str | None = None
    when: str | None = None
    collection_key: str | None = None
    item_label: str = "item"
    default_count: int = 0
    min_items: int = 0
    fields: list[FieldModel] = Field(default_factory=list)
    actions: list[ActionModel] = Field(default_factory=list)


class StageModel(BaseModel):
    id: str
    title: str
    description: str | None = None
    kind: Literal["form_stage", "repeatable_stage", "review_stage", "command_stage", "manual_stage"]
    when: str | None = None
    allow_skip: bool = False
    steps_source: str | None = None
    dependencies: list[str] = Field(default_factory=list)
    fields: list[FieldModel] = Field(default_factory=list)
    repeatables: list[RepeatableModel] = Field(default_factory=list)
    actions: list[ActionModel] = Field(default_factory=list)
    checklist: list[str] = Field(default_factory=list)
    confirmation_prompt: str | None = None


class PhaseModel(BaseModel):
    id: str
    title: str
    description: str | None = None
    when: str | None = None
    stages: list[StageModel] = Field(default_factory=list)


class OutputModel(BaseModel):
    id: str
    path: str
    template: str
    mode: str = "0644"
    when: str | None = None


class ProfileModel(BaseModel):
    id: str
    name: str
    builder: str | None = None
    defaults: dict[str, Any] = Field(default_factory=dict)
    phases: list[PhaseModel] = Field(default_factory=list)
    outputs: list[OutputModel] = Field(default_factory=list)
