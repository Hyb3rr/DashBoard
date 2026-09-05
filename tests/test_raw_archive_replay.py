import hashlib
from pathlib import Path
import subprocess

import pytest

from scripts.ops.replay_raw_archive import RawReplayError, replay_zstd


def _zstd_file(tmp_path: Path, payload: bytes) -> Path:
    source = tmp_path / "chunk.log"
    archive = tmp_path / "chunk.log.zst"
    source.write_bytes(payload)
    subprocess.run(["zstd", "-q", "-3", "-f", str(source), "-o", str(archive)], check=True)
    return archive


def test_replay_streams_raw_chunk_through_pure_normalizer(tmp_path):
    payload = (
        b'203.0.113.10 - - [29/Aug/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 12 "-" "ua"\n'
        b'not an access line\n'
    )
    result = replay_zstd(_zstd_file(tmp_path, payload), "source-a")
    assert result["raw_lines"] == 2
    assert result["raw_bytes"] == len(payload)
    assert result["raw_sha256"] == hashlib.sha256(payload).hexdigest()
    assert result["parsed_events"] == 1
    assert result["skipped_lines"] == 1
    assert result["database_writes"] == 0
    assert result["status"] == "validated"


def test_replay_rejects_missing_input(tmp_path):
    with pytest.raises(RawReplayError, match="existing .zst"):
        replay_zstd(tmp_path / "missing.zst", "source")


def test_replay_does_not_modify_archive(tmp_path):
    archive = _zstd_file(tmp_path, b"not an access line\n")
    before = archive.read_bytes()
    replay_zstd(archive, "source")
    assert archive.read_bytes() == before
