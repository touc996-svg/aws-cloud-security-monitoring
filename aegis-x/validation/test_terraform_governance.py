"""Policy-as-code checks over the Terraform modules (no cloud access or plan required)."""
import re
from pathlib import Path

import hcl2
import pytest

TF_ROOT = Path(__file__).resolve().parents[1] / "terraform"
MODULES = sorted(p for p in TF_ROOT.iterdir() if p.is_dir() and list(p.glob("*.tf")))


def _s(x):
    return x.strip('"') if isinstance(x, str) else x


def parse(module):
    out = {"resource": {}, "variable": {}, "provider": [], "terraform": []}
    for f in sorted(module.glob("*.tf")):
        with open(f) as fh:
            doc = hcl2.load(fh)
        for blk in doc.get("resource", []):
            for rtype, named in blk.items():
                for name, body in named.items():
                    out["resource"][(_s(rtype), _s(name))] = body
        for blk in doc.get("variable", []):
            for name, body in blk.items():
                out["variable"][_s(name)] = body
        out["terraform"] += doc.get("terraform", [])
    return out


def ids(p):
    return p.name


@pytest.mark.parametrize("module", MODULES, ids=ids)
def test_modules_are_parseable_and_pin_versions(module):
    text = "\n".join(f.read_text() for f in module.glob("*.tf"))
    assert re.search(r"required_version\s*=\s*\"[^\"]*<\s*2\.0", text), "pin Terraform below 2.0"
    for provider in re.findall(r"source\s*=\s*\"hashicorp/(\w+)\"", text):
        assert re.search(rf"{provider}\s*=\s*{{[^}}]*version\s*=", text, re.S), f"{provider} must be version-pinned"


@pytest.mark.parametrize("module", MODULES, ids=ids)
def test_billable_switches_default_to_off(module):
    variables = parse(module)["variable"]
    switches = {n: b for n, b in variables.items() if n.startswith("enable_")}
    # sub-toggles documented as only effective under a master switch cannot create anything on their own
    master = {n: b for n, b in switches.items() if "only effective when" not in str(b.get("description", ""))}
    for name, body in master.items():
        assert body.get("default") is False, f"{module.name}.{name} must default to false (billable)"
    # the bootstrap module creates nothing and so needs no switches
    if module.name != "bootstrap":
        assert master, f"{module.name} needs at least one master enable_* switch"


@pytest.mark.parametrize("module", MODULES, ids=ids)
def test_every_gated_resource_is_conditional(module):
    """Resources must honour the switches: count/for_each present on every non-data resource that costs money."""
    parsed = parse(module)
    if module.name == "bootstrap" or not any(n.startswith("enable_") for n in parsed["variable"]):
        pytest.skip("no switches")
    ungated = [f"{t}.{n}" for (t, n), body in parsed["resource"].items()
               if "count" not in body and "for_each" not in body]
    assert not ungated, f"{module.name} has resources that ignore the enable_* switches: {ungated}"


@pytest.mark.parametrize("module", MODULES, ids=ids)
def test_s3_buckets_are_private_encrypted_and_versioned(module):
    res = parse(module)["resource"]
    buckets = [n for (t, n) in res if t == "aws_s3_bucket"]
    for name in buckets:
        for companion in ("aws_s3_bucket_public_access_block", "aws_s3_bucket_server_side_encryption_configuration",
                          "aws_s3_bucket_versioning"):
            assert (companion, name) in res, f"{module.name}: bucket {name} lacks {companion}"
        pab = res[("aws_s3_bucket_public_access_block", name)]
        for flag in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"):
            assert pab.get(flag) is True, f"{module.name}.{name}: {flag} must be true"
        sse = str(res[("aws_s3_bucket_server_side_encryption_configuration", name)])
        assert "aws:kms" in sse, f"{module.name}.{name} must use KMS encryption"


@pytest.mark.parametrize("module", MODULES, ids=ids)
def test_kms_keys_rotate(module):
    for (t, n), body in parse(module)["resource"].items():
        if t == "aws_kms_key":
            assert body.get("enable_key_rotation") is True, f"{module.name}.{n} must rotate"


@pytest.mark.parametrize("module", MODULES, ids=ids)
def test_no_wildcard_iam_grants_except_account_key_admin(module):
    for f in module.glob("*.tf"):
        text = f.read_text()
        for m in re.finditer(r"(Action|actions)\s*=\s*(\[[^\]]*\]|\"[^\"]*\")", text):
            grants = re.findall(r"\"([^\"]+)\"", m.group(2))
            for g in grants:
                if g in ("*", "s3:*", "iam:*", "ec2:*", "lambda:*", "sqs:*"):
                    # s3:* is only acceptable inside an explicit Deny (insecure-transport policy)
                    context = text[max(0, m.start() - 200):m.start()]
                    assert g == "s3:*" and 'effect    = "Deny"' in context, f"{f.name}: wildcard grant {g}"
                if g == "kms:*":
                    context = text[max(0, m.start() - 300):m.start() + 300]
                    assert re.search(r'sid\s*=\s*"AccountAdmin\w*"', context, re.I) and ":root" in text, \
                        f"{f.name}: kms:* only allowed for the account-root key-admin statement"


@pytest.mark.parametrize("module", MODULES, ids=ids)
def test_no_hardcoded_account_ids_or_credentials(module):
    for f in module.glob("*.tf"):
        text = re.sub(r"#.*", "", f.read_text())
        assert not re.search(r"\b\d{12}\b", text), f"{f.name}: hard-coded 12-digit account id"
        assert not re.search(r"(secret|password|token)\s*=\s*\"[^\"$]+\"", text, re.I), f"{f.name}: literal credential"
