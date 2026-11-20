from dataclasses import dataclass


@dataclass(frozen=True)
class CertificateStore:
    id: str
    name: str
