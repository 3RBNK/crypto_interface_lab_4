from dataclasses import dataclass


@dataclass(frozen=True)
class Certificate:
    fingerprint: str
    subject: str
    der: bytes
