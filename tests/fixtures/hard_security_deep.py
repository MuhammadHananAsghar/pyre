# Hard — Deep Security Audit
# This file targets all security rules across complex, nested code patterns.

import hashlib
import os
import pickle
import subprocess
import yaml

DEBUG = True

secret_key = "my-very-secret-production-key"

aws_secret_key = "AKIAiosfodnn7EXAMPLE1234abcdef5678"


class DatabaseManager:
    """A class with multiple security anti-patterns."""

    def __init__(self) -> None:
        self.db_password = "root_password_123"

    def query(self, table: str, user_input: str) -> None:
        sql = f"SELECT * FROM {table} WHERE id = {user_input}"
        print(sql)

    def query_format(self, table: str, value: str) -> None:
        sql = "DELETE FROM {} WHERE name = {}".format(table, value)
        print(sql)

    def query_concat(self, prefix: str) -> None:
        sql = "INSERT INTO logs VALUES (" + prefix
        print(sql)

    def load_cache(self, raw: bytes) -> object:
        return pickle.loads(raw)

    def load_config(self, path: str) -> dict:
        with open(path) as f:
            return yaml.load(f.read())

    def hash_password(self, pw: str) -> str:
        return hashlib.md5(pw.encode()).hexdigest()

    def hash_token(self, token: str) -> str:
        return hashlib.sha1(token.encode()).hexdigest()


def validate_input(x: int) -> None:
    assert x > 0, "x must be positive"


def process(data: str, mode: str) -> None:
    if mode == "eval":
        result = eval(data)
        print(result)
    elif mode == "exec":
        exec(data)


def deploy(target: str) -> None:
    subprocess.call(f"deploy.sh {target}", shell=True)


def read_file(user_path: str) -> str:
    return open(user_path).read()


def resolve_path(base: str, user_dir: str) -> str:
    full = os.path.join(base, user_dir)
    return full


def safe_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_yaml(raw: str) -> dict:
    return yaml.safe_load(raw)


def safe_subprocess(args: list) -> None:
    subprocess.run(args, shell=False)


_ = os.getcwd()
