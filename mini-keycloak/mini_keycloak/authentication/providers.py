"""Provider factory contracts shared by authentication execution registries."""

from collections.abc import Mapping
from typing import Generic, Protocol, TypeVar

from sqlalchemy.orm import Session


ProviderT = TypeVar("ProviderT")


class ProviderFactory(Protocol[ProviderT]):
    def create(self, session: Session) -> ProviderT: ...


class ClassProviderFactory(Generic[ProviderT]):
    def __init__(self, provider_type: type[ProviderT]) -> None:
        self.provider_type = provider_type

    def create(self, session: Session) -> ProviderT:
        return self.provider_type()


class ProviderRegistry(Generic[ProviderT]):
    def __init__(self, factories: Mapping[str, ProviderFactory[ProviderT]]) -> None:
        self.factories = dict(factories)

    def create(self, provider_id: str, session: Session) -> ProviderT:
        factory = self.factories.get(provider_id)
        if factory is None:
            raise ValueError("Invalid authentication request")
        return factory.create(session)


class ActionTokenHandlerRegistry(ProviderRegistry[object]):
    pass
