import os
import subprocess
import sys
from pathlib import Path


def test_database_initialization_and_insert(tmp_path):
    backend_dir = Path(__file__).resolve().parents[1] / "backend"
    script = r'''
from storage.database import initialize_database, insert_traffic, fetch_traffic, get_counts
initialize_database()
insert_traffic({"timestamp":"2026-01-01T12:00:00+00:00", "source":"192.0.2.1", "destination":"192.0.2.2", "protocol":"TCP", "source_port":1234, "destination_port":80, "length":60, "flags":"S"})
assert fetch_traffic(1)[0]["source"] == "192.0.2.1"
assert get_counts()["total_packets"] == 1
'''
    env = os.environ.copy()
    env["CYBER_TREK_DB_PATH"] = str(tmp_path / "test.db")
    subprocess.run([sys.executable, "-c", script], cwd=backend_dir, env=env, check=True)
