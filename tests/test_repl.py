"""Exercise terminal input separately from redirected REPL input."""

import os
import select
import subprocess
import time

import pytest


def test_repl_redirected(r2xsql_bin, fixture_binary):
    result = subprocess.run(
        [str(r2xsql_bin), "--no-analyze", "-s", str(fixture_binary), "-i"],
        input="SELECT 'a\fb' AS literal;\nSELECT 42 AS answer;",
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert "sql> literal\na\fb\nsql> answer\n42\nsql> " in result.stdout
    assert "\x1b" not in result.stdout


@pytest.mark.skipif(os.name == "nt", reason="requires a POSIX pseudo-terminal")
@pytest.mark.parametrize("exit_keys", [b".quit\r", b"\x04", b"\x03"],
                         ids=["quit", "eof", "interrupt"])
def test_repl_ctrl_l(r2xsql_bin, fixture_binary, exit_keys):
    import fcntl
    import pty
    import struct
    import termios

    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    original = termios.tcgetattr(slave)
    proc = subprocess.Popen(
        [str(r2xsql_bin), "--no-analyze", "-s", str(fixture_binary), "-i"],
        stdin=slave, stdout=slave, stderr=slave,
        env=dict(os.environ, TERM="xterm-256color"),
    )

    pending = b""

    def expect(token):
        nonlocal pending
        deadline = time.monotonic() + 10
        while token not in pending:
            remaining = deadline - time.monotonic()
            assert remaining > 0, (token, pending)
            ready, _, _ = select.select([master], [], [], remaining)
            assert ready, (token, pending)
            pending += os.read(master, 65536)
            if b"\x1b[6n" in pending:
                os.write(master, b"\x1b[1;1R")
                pending = pending.replace(b"\x1b[6n", b"")
        output, pending = pending.split(token, 1)
        return output

    try:
        expect(b"sql> ")
        os.write(master, b"\x0c")
        expect(b"\x1b[2J")
        expect(b"sql> ")

        os.write(master, b"SELECT 41")
        expect(b"SELECT 41")
        for _ in range(2):
            os.write(master, b"\x0c")
            expect(b"\x1b[2J")
            expect(b"SELECT 41")
        os.write(master, b"\x7f2 AS answer;\r")
        expect(b"answer\r\n42\r\n")
        expect(b"sql> ")

        os.write(master, b"SELECT 7 AS answer;\x01" + b"\x06" * 7 + b"\x0c")
        expect(b"\x1b[2J")
        expect(b"SELECT 7 AS answer;")
        os.write(master, b"4\x05\r")
        expect(b"answer\r\n47\r\n")
        expect(b"sql> ")

        os.write(master, exit_keys)
        assert proc.wait(timeout=10) == 0
        assert termios.tcgetattr(slave) == original
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        os.close(master)
        os.close(slave)
