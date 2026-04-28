"""Deliberately vulnerable application for e2e scanner testing.

Each section plants a signal for a specific scanner. Do NOT fix these —
they are the test assertions.
"""

# --- gitleaks: private RSA key (always detected by gitleaks) ---
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGcY5unA67hiFg3cOPHTnx4m
HrEaFzpGJIkVOEaj5GCMq1Gvfu0yb8K7hLmFo9fKLFTO3VQzOgaK4M3d3cJg5OX2
-----END RSA PRIVATE KEY-----"""

# --- semgrep: dangerous subprocess with shell=True ---
import subprocess
def run_command(cmd: str) -> str:
    return subprocess.check_output(cmd, shell=True, text=True)


# --- complexity/lizard: high cyclomatic complexity (CCN > 15) ---
def overly_complex_function(a, b, c, d, e, f, g, h):
    result = 0
    if a > 0:
        result += 1
    elif a < -10:
        result -= 1
    if b > 0:
        result += 2
    elif b < -10:
        result -= 2
    if c > 0:
        result += 3
    elif c < -10:
        result -= 3
    if d > 0:
        result += 4
    elif d < -10:
        result -= 4
    if e > 0:
        result += 5
    elif e < -10:
        result -= 5
    if f > 0:
        result += 6
    elif f < -10:
        result -= 6
    if g > 0:
        result += 7
    elif g < -10:
        result -= 7
    if h > 0:
        result += 8
    elif h < -10:
        result -= 8
    if result > 20:
        return result * 2
    return result


# --- mypy: deliberate type error ---
def add_numbers(x: int, y: int) -> int:
    return x + y


broken_result: int = add_numbers("not", "ints")  # type: ignore[arg-type] — planted for mypy
