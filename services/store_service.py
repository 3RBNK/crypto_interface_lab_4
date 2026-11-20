from collections.abc import Iterator
from hashlib import sha256
from pathlib import Path

import chilkat2

from models.certificate import Certificate
from models.certificate_store import CertificateStore


STORES = (
    CertificateStore("/usr/local/share/ca-certificates", "Локальные доверенные сертификаты"),
    CertificateStore("/etc/ssl/certs", "Общее системное хранилище"),
)


class StoreService:
    def list_stores(self) -> list[CertificateStore]:
        return [store for store in STORES if Path(store.id).is_dir()]

    def list_certificates(self, store_id: str) -> list[Certificate]:
        root = Path(store_id)
        if str(root) not in {store.id for store in STORES}:
            raise ValueError(f"Неизвестное хранилище {store_id!r}. Используйте list-stores.")
        if not root.is_dir():
            raise ValueError(f"Каталог хранилища {str(root)!r} недоступен.")

        certificates: dict[str, Certificate] = {}
        for directory, _, filenames in root.walk(on_error=_raise_walk_error):
            for filename in filenames:
                path = directory / filename
                if not path.is_file():
                    continue
                try:
                    data = path.read_bytes()
                except FileNotFoundError:
                    continue
                for cert in _read_certificates(data):
                    encoded = cert.ExportCertDer()
                    if not encoded:
                        continue
                    der = bytes(encoded)
                    fingerprint = sha256(der).hexdigest()
                    if fingerprint not in certificates:
                        subject = cert.SubjectDN or "(владелец не указан)"
                        certificates[fingerprint] = Certificate(fingerprint, subject, der)

        return sorted(certificates.values(), key=lambda cert: (cert.subject, cert.fingerprint))

    def get_certificate(self, store_id: str, fingerprint: str) -> Certificate:
        fingerprint = fingerprint.replace(":", "").lower()
        for cert in self.list_certificates(store_id):
            if cert.fingerprint == fingerprint:
                return cert
        raise ValueError(f"Сертификат с отпечатком {fingerprint!r} в этом хранилище не найден.")


def _raise_walk_error(error: OSError) -> None:
    raise error


def _read_certificates(data: bytes) -> Iterator[chilkat2.Cert]:
    if b"-----BEGIN CERTIFICATE-----" in data:
        store = chilkat2.CertStore()
        if store.LoadPemStr(data.decode("ascii", errors="replace")):
            for index in range(store.NumCertificates):
                cert = chilkat2.Cert()
                if store.GetCert(index, cert):
                    yield cert
    elif data.startswith(b"\x30"):
        cert = chilkat2.Cert()
        if cert.LoadFromBinary(data):
            yield cert
