from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol


@dataclass
class PasskeyCredential:
    id: int | str | None
    user_id: int | str

    user_handle: bytes

    credential_id: bytes
    public_key: bytes

    sign_count: int

    name: str | None = None
    transports: tuple[str, ...] = ()

    created_at: datetime = field(
        default_factory=lambda: (
            datetime.now(timezone.utc)
        )
    )

    last_used_at: datetime | None = None


class PasskeyStore(Protocol):
    def create(
        self,
        credential: PasskeyCredential,
    ) -> PasskeyCredential:
        ...

    def get_by_credential_id(
        self,
        credential_id: bytes,
    ) -> PasskeyCredential | None:
        ...

    def list_for_user(
        self,
        user_id: int | str,
    ) -> list[PasskeyCredential]:
        ...

    def update_usage(
        self,
        credential_id: bytes,
        *,
        sign_count: int,
        last_used_at: datetime,
    ) -> None:
        ...

    def delete(
        self,
        user_id: int | str,
        credential_id: bytes,
    ) -> bool:
        ...