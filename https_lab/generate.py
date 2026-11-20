import argparse
import secrets
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory


LAB_DIR = Path(__file__).resolve().parent
PKI_DIR = LAB_DIR / "pki"
CONFIG = LAB_DIR / "openssl.cnf"


def openssl(directory: Path, *arguments: str) -> None:
    subprocess.run(["openssl", *arguments], cwd=directory, check=True)


def issue_ca(directory: Path) -> None:
    openssl(
        directory, "req", "-new", "-x509", "-newkey", "rsa:3072", "-nodes",
        "-config", str(CONFIG), "-extensions", "lab_ca", "-sha256", "-days", "365",
        "-subj", "/CN=127.0.0.1", "-keyout", "root_ca.key", "-out", "root_ca.crt",
    )
    openssl(
        directory, "x509", "-in", "root_ca.crt", "-outform", "PEM",
        "-out", "root_ca.pem",
    )


def issue_server(directory: Path, ca_directory: Path, localhost: bool) -> None:
    subject = "/CN=localhost" if localhost else "/CN=Lab 4 HTTPS"
    extensions = "lab_localhost" if localhost else "lab_server"
    identity = ("-verify_hostname", "localhost") if localhost else ("-verify_ip", "127.0.0.1")
    csr = str(directory.parent / "server.csr")
    ca_certificate = str(ca_directory / "root_ca.pem")
    ca_key = str(ca_directory / "root_ca.key")

    openssl(
        directory, "req", "-new", "-newkey", "rsa:2048", "-nodes",
        "-config", str(CONFIG), "-sha256", "-subj", subject,
        "-keyout", "server.key", "-out", csr,
    )
    openssl(
        directory, "x509", "-req", "-in", csr,
        "-CA", ca_certificate, "-CAkey", ca_key,
        "-set_serial", f"0x01{secrets.token_hex(15)}", "-sha256", "-days", "30",
        "-extfile", str(CONFIG), "-extensions", extensions, "-out", "server.crt",
    )
    openssl(
        directory, "verify", "-CAfile", ca_certificate, "-purpose", "sslserver",
        *identity, "server.crt",
    )


def generate(localhost: bool) -> Path:
    destination = PKI_DIR / "localhost" if localhost else PKI_DIR
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"Каталог {destination} уже существует. Используйте выпущенные сертификаты.")
    if localhost and not all((PKI_DIR / name).is_file() for name in ("root_ca.pem", "root_ca.key")):
        raise FileNotFoundError("Сначала выпустите CA командой python3 https_lab/generate.py.")

    with TemporaryDirectory(dir=LAB_DIR, prefix=".pki-") as temp_dir:
        certificates = Path(temp_dir) / "pki"
        certificates.mkdir(mode=0o700)
        if not localhost:
            issue_ca(certificates)
        ca_directory = PKI_DIR if localhost else certificates
        issue_server(certificates, ca_directory, localhost)
        certificates.rename(destination)
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description="Выпуск сертификатов для лабораторного HTTPS-сервера.")
    parser.add_argument("--localhost", action="store_true", help="Выпустить сертификат localhost от существующего CA.")
    args = parser.parse_args()
    try:
        destination = generate(args.localhost)
    except subprocess.CalledProcessError as error:
        print(f"Команда OpenSSL завершилась с кодом {error.returncode}.", file=sys.stderr)
        return 1
    except OSError as error:
        print(error, file=sys.stderr)
        return 1

    print(f"Сертификаты и ключи сохранены в {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
