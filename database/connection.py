"""MySQL connection factory configured from environment variables."""

import os

import mysql.connector
from dotenv import load_dotenv

load_dotenv()


def get_connection():
    required = ("DB_HOST", "DB_USER", "DB_PASSWORD", "DB_NAME")
    missing = [name for name in required if not os.getenv(name)]
    if missing:
        raise RuntimeError(f"Missing database configuration: {', '.join(missing)}")
    return mysql.connector.connect(
        host=os.environ["DB_HOST"],
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        database=os.environ["DB_NAME"],
        connection_timeout=10,
        charset="utf8mb4",
        use_unicode=True,
    )
