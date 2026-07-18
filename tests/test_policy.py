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


# --- declarative tool-argument schema --------------------------------------


def test_tool_declares_args_and_allowlists():
    p = (
        Policy.builder("p")
        .tool("filesystem.read", reads="path")
        .tool("filesystem.delete", writes="path")
        .tool("http.fetch", network="url")
        .build()
    )
    # Declaring a tool allowlists it, so exactly these three are permitted.
    assert p.allowed_tools == frozenset(
        {"filesystem.read", "filesystem.delete", "http.fetch"}
    )
    assert p.tool_allowed("filesystem.read") is True
    assert p.tool_allowed("shell.exec") is False
    # And the argument mapping is recorded.
    assert p.args_for("filesystem.read").reads == ("path",)
    assert p.args_for("filesystem.delete").writes == ("path",)
    assert p.args_for("http.fetch").network == ("url",)


def test_tool_allow_false_declares_without_allowlisting():
    p = Policy.builder("p").tool("x", writes="path", allow=False).build()
    assert p.allowed_tools is None  # no allowlist was enabled
    assert p.args_for("x").writes == ("path",)


def test_tool_args_accept_a_list_of_names():
    p = Policy.builder("p").tool("copy", reads=["src"], writes=["dst", "tmp"]).build()
    spec = p.args_for("copy")
    assert spec.reads == ("src",)
    assert spec.writes == ("dst", "tmp")
    assert spec.declared is True


def test_args_for_undeclared_tool_is_empty():
    p = Policy.builder("p").build()
    spec = p.args_for("nope")
    assert spec.reads == () and spec.writes == () and spec.network == ()
    assert spec.declared is False


def test_deny_tool_wins_over_allowlist():
    p = Policy.builder("p").allow_tools("a", "b").deny_tool("b").build()
    assert p.tool_allowed("a") is True
    assert p.tool_allowed("b") is False  # denial beats the allowlist


def test_deny_tool_beats_tool_declaration():
    p = Policy.builder("p").tool("filesystem.delete", writes="path").deny_tools(
        "filesystem.delete"
    ).build()
    assert p.tool_allowed("filesystem.delete") is False


def test_from_yaml_tool_args_and_deny(tmp_path):
    yaml_text = """
name: mcp
tools:
  allow: [fs.read]
  deny: [shell.exec]
  args:
    fs.read:
      reads: path
    fs.delete:
      writes: [path, backup]
    web.get:
      network: url
"""
    f = tmp_path / "p.yaml"
    f.write_text(yaml_text, encoding="utf-8")
    p = Policy.from_yaml(str(f))
    assert p.args_for("fs.read").reads == ("path",)
    assert p.args_for("fs.delete").writes == ("path", "backup")
    assert p.args_for("web.get").network == ("url",)
    # Declared tools are allowlisted alongside the explicit allow list.
    assert p.tool_allowed("fs.read") is True
    assert p.tool_allowed("fs.delete") is True
    assert p.tool_allowed("shell.exec") is False  # explicit deny
    assert p.tool_allowed("never.declared") is False


def test_from_dict_rejects_unknown_tool_arg_key():
    with pytest.raises(PolicyError):
        Policy.from_dict(
            {"name": "x", "tools": {"args": {"t": {"reeds": "path"}}}}
        )


def test_from_dict_rejects_unknown_tools_key():
    with pytest.raises(PolicyError):
        Policy.from_dict({"name": "x", "tools": {"allowed": ["a"]}})


# --- network host rules -----------------------------------------------------


def test_network_allowed_default_deny():
    p = Policy.builder("p").deny_network().build()
    assert p.network_allowed("https://example.com") is False
    assert p.network_allowed(None) is False  # forced-network, unknown host


def test_network_allowed_default_allow():
    p = Policy.builder("p").allow_network().build()
    assert p.network_allowed("https://example.com") is True
    assert p.network_allowed(None) is True


def test_network_allow_hosts_exact_and_subdomain():
    p = Policy.builder("p").allow_hosts("example.com").build()
    assert p.network_allowed("https://example.com/x") is True
    assert p.network_allowed("https://api.example.com") is True
    assert p.network_allowed("https://evil.com") is False
    assert p.network_allowed("https://notexample.com") is False


def test_network_deny_hosts_win():
    p = Policy.builder("p").allow_network().deny_hosts("attacker.example").build()
    assert p.network_allowed("https://ok.com") is True
    assert p.network_allowed("https://attacker.example/x") is False


def test_network_hosts_normalize_urls_and_case():
    # A URL or mixed-case host as a rule is reduced to a comparable host.
    p = Policy.builder("p").allow_hosts("https://API.Example.com/ignored").build()
    assert p.network_allow_hosts == frozenset({"api.example.com"})
    assert p.network_allowed("http://api.example.com:8080/y") is True


def test_from_yaml_network_host_rules(tmp_path):
    yaml_text = """
name: net
network:
  default: deny
  allow_hosts: [api.example.com, docs.python.org]
  deny_hosts: [api.example.com/secret]
tools:
  args:
    web.get: { network: url }
"""
    f = tmp_path / "p.yaml"
    f.write_text(yaml_text, encoding="utf-8")
    p = Policy.from_yaml(str(f))
    assert "api.example.com" in p.network_allow_hosts
    assert "docs.python.org" in p.network_allow_hosts
    assert p.network_allowed("https://docs.python.org/3/") is True
    assert p.network_allowed("https://elsewhere.com") is False


def test_from_dict_rejects_unknown_network_key():
    with pytest.raises(PolicyError):
        Policy.from_dict({"name": "x", "network": {"allowlist": []}})


def test_network_host_helpers():
    from asphallea.policy import host_matches, network_host

    assert network_host("https://a.b.com:443/p") == "a.b.com"
    assert network_host("a.b.com:80") == "a.b.com"
    assert network_host("A.B.com") == "a.b.com"
    assert host_matches("api.example.com", "example.com") is True
    assert host_matches("notexample.com", "example.com") is False


def test_from_dict_requires_name():
    with pytest.raises(PolicyError):
        Policy.from_dict({"tools": {"allow": ["a"]}})
