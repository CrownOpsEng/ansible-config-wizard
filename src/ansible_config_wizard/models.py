from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class SourceModel(BaseModel):
    kind: Literal["prompt", "generate", "optional_prompt", "external_vault"] = "prompt"
    generator: str | None = None
    driver: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)


class FieldModel(BaseModel):
    id: str
    label: str
    type: Literal["text", "password", "confirm", "select", "list", "key_value", "int"] = "text"
    help: str | None = None
    required: bool = False
    secret: bool = False
    when: str | None = None
    default: Any = None
    default_template: str | None = None
    choices: list[str] = Field(default_factory=list)
    separator: str = ","
    source: SourceModel = Field(default_factory=SourceModel)


class SectionModel(BaseModel):
    id: str
    title: str
    description: str | None = None
    kind: Literal["fields", "repeatable"] = "fields"
    when: str | None = None
    fields: list[FieldModel] = Field(default_factory=list)
    collection_key: str | None = None
    item_label: str = "item"
    default_count: int = 0
    min_items: int = 0


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
    sections: list[SectionModel]
    outputs: list[OutputModel]
