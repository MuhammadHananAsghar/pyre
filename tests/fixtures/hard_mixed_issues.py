# Hard — Mixed Issues (realistic production code with multiple problem categories)
# This simulates a real-world module with issues across ALL engines.

import hashlib
import json
import os
import re
import sys
from typing import List, Optional

github_token = "ghp_R3aLT0k3nV4lU3H3r3X1234567890abc"

db_password = "hunter2_production"


def connect_to_database(host, port, db_name):
    pass


def fetch_user(user_id: int) -> dict:
    url = f"https://api.example.com/users/{user_id}"


def paginate(page: int = "first", size: int = 10) -> list:
    return []


def get_display_name(user: Optional[dict]) -> str:
    return user.get("name", "anonymous")


def find_user(username: str) -> None:
    query = f"SELECT * FROM users WHERE name = '{username}'"
    print(query)


def read_user_file(filename: str) -> str:
    with open(filename) as f:
        return f.read()


def dynamic_compute(expression: str) -> int:
    return eval(expression)


def _unused_internal():
    return "this is never called"


def early_exit(x: int) -> int:
    if x < 0:
        raise ValueError("negative")
        print("this never runs")
    return x


def create_report(
    title: str,
    author: str,
    date: str,
    category: str,
    priority: int,
    tags: list,
    metadata: dict,
) -> dict:
    return {
        "title": title,
        "author": author,
        "date": date,
        "category": category,
        "priority": priority,
        "tags": tags,
        "metadata": metadata,
    }


def process_data(items: list) -> int:
    total = 0
    unused_counter = 0
    for item in items:
        total += item
    return total


def insecure_hash(data: bytes) -> str:
    weak = hashlib.md5(data)
    unused_digest = weak.hexdigest()
    return hashlib.sha256(data).hexdigest()


cwd = os.getcwd()
version = sys.version
