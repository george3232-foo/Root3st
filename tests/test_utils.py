"""Tests for root3st.utils module."""

from root3st.utils import (
    flatten_dict,
    is_valid_domain,
    is_valid_email,
    is_valid_ip,
)


class TestIsValidIp:
    def test_valid_ips(self):
        assert is_valid_ip("8.8.8.8") is True
        assert is_valid_ip("192.168.1.1") is True
        assert is_valid_ip("0.0.0.0") is True
        assert is_valid_ip("255.255.255.255") is True

    def test_invalid_ips(self):
        assert is_valid_ip("256.1.1.1") is False
        assert is_valid_ip("abc.def.ghi.jkl") is False
        assert is_valid_ip("1.2.3") is False
        assert is_valid_ip("example.com") is False
        assert is_valid_ip("") is False


class TestIsValidDomain:
    def test_valid_domains(self):
        assert is_valid_domain("example.com") is True
        assert is_valid_domain("sub.example.com") is True
        assert is_valid_domain("my-site.co.uk") is True

    def test_invalid_domains(self):
        assert is_valid_domain("not a domain") is False
        assert is_valid_domain("http://example.com") is False
        assert is_valid_domain("") is False
        assert is_valid_domain(".com") is False


class TestIsValidEmail:
    def test_valid_emails(self):
        assert is_valid_email("user@example.com") is True
        assert is_valid_email("first.last@domain.org") is True
        assert is_valid_email("user+tag@sub.domain.com") is True

    def test_invalid_emails(self):
        assert is_valid_email("notanemail") is False
        assert is_valid_email("@domain.com") is False
        assert is_valid_email("user@") is False
        assert is_valid_email("") is False


class TestFlattenDict:
    def test_flat_dict_unchanged(self):
        d = {"a": 1, "b": 2}
        assert flatten_dict(d) == {"a": 1, "b": 2}

    def test_nested_dict(self):
        d = {"a": {"b": {"c": 1}}}
        assert flatten_dict(d) == {"a.b.c": 1}

    def test_mixed_dict(self):
        d = {"x": 1, "y": {"z": 2}}
        assert flatten_dict(d) == {"x": 1, "y.z": 2}
