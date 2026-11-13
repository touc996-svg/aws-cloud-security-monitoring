"""Static guarantees about what the AEGIS-X code is allowed to do."""
import ast
import re
import subprocess
from pathlib import Path

import pytest

AEGIS = Path(__file__).resolve().parents[1]
REPO = AEGIS.parent

OFFLINE_CODE = [
    *sorted((AEGIS / "integrations" / "azure").glob("*.py")),
    *sorted((AEGIS / "integrations" / "gcp").glob("*.py")),
    AEGIS / "integrations" / "aws" / "guardduty_normalizer.py",
    AEGIS / "integrations" / "aws" / "securityhub_normalizer.py",
    *sorted((AEGIS / "pipeline").glob("*.py")),
]
FORBIDDEN = {"boto3", "botocore", "requests", "urllib3", "http", "socket", "httpx", "aiohttp",
             "azure", "google", "subprocess", "ftplib", "smtplib"}


def imported_roots(path):
    tree = ast.parse(path.read_text())
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots


@pytest.mark.parametrize("path", OFFLINE_CODE, ids=lambda p: str(p.relative_to(AEGIS)))
def test_normalizers_and_pipeline_cannot_reach_the_network_or_clouds(path):
    bad = imported_roots(path) & FORBIDDEN
    assert not bad, f"{path.name} imports {sorted(bad)}; normalization and correlation must stay offline and credential-free"


def test_only_the_lambda_handler_may_use_boto3_and_only_lazily():
    src = (AEGIS / "integrations" / "aws" / "lambda_handler.py").read_text()
    tree = ast.parse(src)
    top_level = {n.names[0].name for n in tree.body if isinstance(n, ast.Import)}
    assert "boto3" not in top_level, "boto3 must be imported lazily inside the handler"


def test_lambda_handler_has_no_destructive_or_privilege_calls():
    src = (AEGIS / "integrations" / "aws" / "lambda_handler.py").read_text()
    for banned in ("delete_object", "put_bucket_policy", "iam", "assume_role", "terminate", "stop_instances"):
        assert banned not in src.lower(), banned


def tracked_files():
    out = subprocess.run(["git", "ls-files"], cwd=REPO, capture_output=True, text=True, check=True).stdout
    return [REPO / p for p in out.splitlines()]


def test_no_secret_material_is_tracked():
    patterns = {
        "aws access key id": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        "private key": re.compile(r"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----"),
        "aws secret": re.compile(r"aws_secret_access_key\s*=\s*[A-Za-z0-9/+]{30,}"),
    }
    allowed = {"ASIAEXAMPLEEXAMPLE", "AKIAIOSFODNN7EXAMPLE"}  # documentation placeholders used in fixtures
    hits = []
    for f in tracked_files():
        if f.suffix in {".png", ".jpg", ".pdf", ".zip"} or not f.is_file():
            continue
        text = f.read_text(errors="ignore")
        for label, rx in patterns.items():
            for m in rx.finditer(text):
                if m.group(0) not in allowed and not any(a in m.group(0) for a in allowed):
                    hits.append(f"{f.relative_to(REPO)}: {label}")
    assert not hits, hits


def test_no_state_or_variable_files_are_tracked():
    bad = [str(f.relative_to(REPO)) for f in tracked_files()
           if f.name.endswith((".tfstate", ".tfstate.backup", ".tfvars")) or f.name == "terraform.tfstate"]
    assert not bad, bad
