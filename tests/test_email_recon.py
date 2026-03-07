"""Tests for root3st.modules.email_recon module."""

from root3st.modules.email_recon import parse_email


class TestParseEmail:
    def test_standard_email(self):
        local, domain = parse_email("user@example.com")
        assert local == "user"
        assert domain == "example.com"

    def test_complex_local(self):
        local, domain = parse_email("first.last+tag@sub.domain.org")
        assert local == "first.last+tag"
        assert domain == "sub.domain.org"

    def test_no_at_sign(self):
        local, domain = parse_email("nodomain")
        assert local == "nodomain"
        assert domain == ""
