from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderReference:
    driver: str
    ref: dict[str, str]


class ExternalVaultProvider:
    name = "external_vault"

    def describe(self) -> str:
        return self.name

    def validate_access(self) -> None:
        raise NotImplementedError("External vault access is not implemented yet.")

    def resolve(self, reference: ProviderReference) -> str:
        raise NotImplementedError("External vault access is not implemented yet.")


class ProviderRegistry:
    def __init__(self) -> None:
        self._providers: dict[str, ExternalVaultProvider] = {}

    def register(self, provider: ExternalVaultProvider) -> None:
        self._providers[provider.name] = provider

    def get(self, name: str) -> ExternalVaultProvider:
        if name not in self._providers:
            raise KeyError(f"Unknown provider driver: {name}")
        return self._providers[name]

