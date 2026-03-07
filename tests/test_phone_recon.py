"""Tests for root3st.modules.phone_recon module."""

from root3st.modules.phone_recon import (
    analyse_format,
    identify_country,
    normalise_number,
)


class TestNormaliseNumber:
    def test_strips_formatting(self):
        assert normalise_number("+1 (555) 123-4567") == "+15551234567"
        assert normalise_number("44-20-7946-0958") == "442079460958"

    def test_preserves_leading_plus(self):
        assert normalise_number("+44123456").startswith("+")


class TestIdentifyCountry:
    def test_us_number(self):
        result = identify_country("+15551234567")
        assert result["country"] == "US/CA"
        assert result["country_code"] == "+1"

    def test_uk_number(self):
        result = identify_country("+442079460958")
        assert result["country"] == "GB"

    def test_unknown(self):
        result = identify_country("000")
        assert result["country"] == "unknown"


class TestAnalyseFormat:
    def test_international(self):
        result = analyse_format("+1 555 123 4567")
        assert result["is_international"] is True
        assert result["normalised"] == "+15551234567"
        assert result["country"] == "US/CA"

    def test_local_format(self):
        result = analyse_format("5551234567")
        assert result["is_international"] is False
