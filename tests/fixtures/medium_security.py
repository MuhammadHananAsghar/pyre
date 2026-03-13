# Medium — Security Issues
# Expected: multiple SEC findings

import hashlib
import pickle
import subprocess
import yaml


def process_input(data: str) -> None:
    result = eval(data)
    print(result)


password = "super_secret_123"
api_key = "sk-1234567890abcdef"


def load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.load(f.read())


def load_cache(data: bytes) -> object:
    return pickle.loads(data)


def hash_data(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def run_command(cmd: str) -> None:
    subprocess.call(cmd, shell=True)
