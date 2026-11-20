import argparse
import sys

from services.crypto_service import CryptoService
from services.store_service import StoreService


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Просмотр хранилищ сертификатов Linux и шифрование сообщений.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list-stores", help="Показать доступные хранилища.")

    list_certs = commands.add_parser(
        "list-certs", help="Показать отпечатки SHA-256 и владельцев сертификатов.",
    )
    list_certs.add_argument("store_id", help="Путь к хранилищу из list-stores.")

    encrypt = commands.add_parser(
        "encrypt", help="Зашифровать сообщение (RSA-OAEP с SHA-256, вывод в Base64).",
    )
    encrypt.add_argument("store_id", help="Путь к хранилищу из list-stores.")
    encrypt.add_argument("fingerprint", help="Отпечаток SHA-256 из list-certs.")
    encrypt.add_argument("message", help="Исходный текст в UTF-8.")

    args = parser.parse_args(argv)
    stores = StoreService()
    try:
        if args.command == "list-stores":
            for store in stores.list_stores():
                print(f"{store.id}\t{store.name}")
        elif args.command == "list-certs":
            for certificate in stores.list_certificates(args.store_id):
                print(f"{certificate.fingerprint}\t{certificate.subject}")
        else:
            certificate = stores.get_certificate(args.store_id, args.fingerprint)
            print(CryptoService().encrypt(certificate, args.message))
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 1
    return 0
