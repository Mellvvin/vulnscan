import pytest

from vulnscan.portscan import parse_ports, probe_port, scan_ports
from vulnscan.scope import ScopeError, check_authorization, expand_targets


def test_parse_ports_variants():
    assert parse_ports("22,80,8000-8002") == [22, 80, 8000, 8001, 8002]
    assert 80 in parse_ports("top")
    assert len(parse_ports("all")) == 65535


@pytest.mark.parametrize("bad", ["0", "70000", "90-80", "abc"])
def test_parse_ports_rejects_bad_input(bad):
    with pytest.raises(ValueError):
        parse_ports(bad)


def test_cidr_expansion_and_dedup():
    targets = expand_targets(["10.0.0.0/30", "10.0.0.1"])
    assert [t.address for t in targets] == ["10.0.0.1", "10.0.0.2"]


def test_target_file(tmp_path):
    f = tmp_path / "targets.txt"
    f.write_text("# lab\n127.0.0.1\n\n192.168.1.5  # printer\n")
    assert [t.address for t in expand_targets([str(f)])] == ["127.0.0.1", "192.168.1.5"]


def test_oversized_range_rejected():
    with pytest.raises(ScopeError):
        expand_targets(["10.0.0.0/8"])


def test_public_targets_refused_without_flag():
    targets = expand_targets(["8.8.8.8"])
    with pytest.raises(ScopeError, match="allow-public"):
        check_authorization(targets, allow_public=False)
    assert check_authorization(targets, allow_public=True)  # returns the public list


def test_private_and_loopback_allowed():
    targets = expand_targets(["127.0.0.1", "192.168.0.10", "10.1.2.3"])
    assert check_authorization(targets, allow_public=False) == []


def test_scan_and_probe_open_port(lab_port):
    assert scan_ports("127.0.0.1", [lab_port, 1], timeout=0.5) == [lab_port]
    info = probe_port("127.0.0.1", lab_port, timeout=1.0)
    assert info.http and not info.tls
    assert "Apache/2.4.49" in info.banner
