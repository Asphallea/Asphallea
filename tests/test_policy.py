"""Tests for the policy model, builder, and YAML loader."""

from __future__ import annotations

import os

import pytest

from asphallea import Policy, PolicyError, RateLimit, ResourceLimits


def test_builder_basic():
    p = (
        Policy.builder("p")
        .allow_tools("a", "b")
        .deny_network()
        .max_calls("a", 3)
        .rate_limit("a", per_minute=10)
        .spend_cap("paid", 2)
        .timeout(5)
        .build()
    )
    assert p.name == "p"
    assert p.allowed_tools == frozenset({"a", "b"})
    assert p.network == "deny"
    assert p.max_calls == {"a": 3}
    assert p.rate_limits["a"] == RateLimit(10, 60.0)
    assert p.spend_caps == {"paid": 2}
    assert p.timeout_seconds == 5.0


def test_no_allowlist_means_unrestricted():
    p = Policy.builder("p").build()
    assert p.allowed_tools is None
    assert p.tool_allowed("anything") is True


def test_allowlist_denies_unlisted():
    p = Policy.builder("p").allow_tool("known").build()
    assert p.tool_allowed("known") is True
    assert p.tool_allowed("unknown") is False


def test_paths_normalized_absolute(tmp_path):
    rel = os.path.relpath(str(tmp_path))
    p = Policy.builder("p").read_paths(rel).build()
    assert p.read_paths[0] == os.path.realpath(str(tmp_path))


def test_write_path_implies_read(tmp_path):
    w = str(tmp_path / "out")
    p = Policy.builder("p").write_paths(w).build()
    norm = os.path.realpath(w)
    assert norm in p.write_paths
    assert norm in p.read_paths  # write also grants read


def test_immutable():
    p = Policy.builder("p").build()
    with pytest.raises(Exception):
        p.name = "other"  # type: ignore[misc]


def test_invalid_network_rejected():
    with pytest.raises(PolicyError):
        Policy(name="x", network="maybe")


def test_rate_limit_requires_exactly_one_unit():
    with pytest.raises(PolicyError):
        Policy.builder("p").rate_limit("a", per_minute=1, per_second=1)
    with pytest.raises(PolicyError):
        Policy.builder("p").rate_limit("a")


def test_timeout_must_be_positive():
    with pytest.raises(PolicyError):
        Policy.builder("p").timeout(0)


def test_resource_limits_to_core_json():
    limits = ResourceLimits(cpu_seconds=2, memory_mb=8, max_file_size_mb=1)
    j = limits.to_core_json()
    assert j["cpu_seconds"] == 2
    assert j["memory_bytes"] == 8 * 1024 * 1024
    assert j["max_file_size_bytes"] == 1 * 1024 * 1024
    assert "max_processes" not in j


def test_to_core_json_shape(tmp_path):
    p = (
        Policy.builder("p")
        .read_paths(str(tmp_path))
        .write_paths(str(tmp_path / "out"))
        .deny_network()
        .limits(memory_mb=16)
        .build()
    )
    core = p.to_core_json()
    assert core["network"] == "deny"
    assert core["filesystem"]["read"]
    assert core["filesystem"]["write"]
    assert core["limits"]["memory_bytes"] == 16 * 1024 * 1024


def test_from_yaml(tmp_path):
    yaml_text = """
name: y
tools:
  allow: [read_file, search]
filesystem:
  read: ["{ws}"]
  write: ["{out}"]
network:
  default: deny
limits:
  timeout_seconds: 15
  calls:
    search: 5
  rate:
    search:
      per_minute: 20
  memory_mb: 128
spend:
  search:
    max_calls: 5
""".format(ws=str(tmp_path).replace("\\", "/"), out=str(tmp_path / "out").replace("\\", "/"))
    f = tmp_path / "policy.yaml"
    f.write_text(yaml_text, encoding="utf-8")
    p = Policy.from_yaml(str(f))
    assert p.name == "y"
    assert p.allowed_tools == frozenset({"read_file", "search"})
    assert p.max_calls["search"] == 5
    assert p.rate_limits["search"] == RateLimit(20, 60.0)
    assert p.spend_caps["search"] == 5
    assert p.timeout_seconds == 15.0
    assert p.limits.memory_mb == 128


def test_from_dict_rejects_unknown_keys():
    with pytest.raises(PolicyError):
        Policy.from_dict({"name": "x", "bogus": 1})


def test_from_dict_requires_name():
    with pytest.raises(PolicyError):
        Policy.from_dict({"tools": {"allow": ["a"]}})
