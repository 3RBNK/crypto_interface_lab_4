import base64
import subprocess
from hashlib import sha256
from tempfile import NamedTemporaryFile

import chilkat2

from models.certificate import Certificate


class CryptoService:
    def encrypt(self, certificate: Certificate, message: str) -> str:
        cert = chilkat2.Cert()
        if not cert.LoadFromBinary(certificate.der):
            raise ValueError("Не удалось прочитать сертификат.")
        public_key = cert.ExportPublicKey()
        if public_key is None or public_key.KeyType != "rsa":
            raise ValueError("Для шифрования RSA-OAEP выберите сертификат с ключом RSA.")

        plaintext = message.encode("utf-8")
        key_bytes = (public_key.KeySize + 7) // 8
        max_length = key_bytes - 2 * sha256().digest_size - 2
        if len(plaintext) > max_length:
            raise ValueError(
                f"Сообщение занимает {len(plaintext)} байт UTF-8. "
                f"Ключ допускает до {max_length} байт при RSA-OAEP с SHA-256.",
            )

        with NamedTemporaryFile(suffix=".der") as cert_file:
            cert_file.write(certificate.der)
            cert_file.flush()
            try:
                result = subprocess.run(
                    [
                        "openssl", "pkeyutl", "-encrypt",
                        "-certin", "-keyform", "DER", "-inkey", cert_file.name,
                        "-pkeyopt", "rsa_padding_mode:oaep",
                        "-pkeyopt", "rsa_oaep_md:sha256",
                        "-pkeyopt", "rsa_mgf1_md:sha256",
                    ],
                    input=plaintext,
                    capture_output=True,
                    check=False,
                )
            except FileNotFoundError as error:
                raise RuntimeError("Для шифрования требуется команда openssl.") from error

        if result.returncode:
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"OpenSSL завершился с кодом {result.returncode}. {detail}")
        return base64.b64encode(result.stdout).decode("ascii")
