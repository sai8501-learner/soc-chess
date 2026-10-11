import subprocess
import sys


def test_spark_manager_import_is_non_blocking():
    repo_root = r"c:\wamp64\www\soc-chess"
    code = f'''
import sys
sys.path.insert(0, {repo_root!r})
import backend.spark_engine.spark_manager
print("IMPORT_OK")
'''

    completed = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=12,
        cwd=repo_root,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout
    assert "IMPORT_OK" in completed.stdout
