"""Tests for root3st.dorks_recon module."""

from root3st.modules import dorks_recon


class TestBuildDorksForDomain:
    def test_domain_dorks_count(self):
        result = dorks_recon.build_dorks_for_domain("example.com")
        assert result["type"] == "domain"
        assert result["target"] == "example.com"
        # Should have multiple dork types
        assert len(result["dorks"]) >= 15

    def test_domain_dorks_contain_google(self):
        result = dorks_recon.build_dorks_for_domain("example.com")
        dork_values = list(result["dorks"].values())
        assert any("google.com" in url for url in dork_values)

    def test_domain_dorks_contain_archived(self):
        result = dorks_recon.build_dorks_for_domain("example.com")
        assert "archived" in result["dorks"]
        assert "web.archive.org" in result["dorks"]["archived"]


class TestBuildDorksForEmail:
    def test_email_dorks_count(self):
        result = dorks_recon.build_dorks_for_email("test@example.com")
        assert result["type"] == "email"
        assert result["target"] == "test@example.com"
        assert len(result["dorks"]) >= 8

    def test_email_dorks_include_github(self):
        result = dorks_recon.build_dorks_for_email("user@test.com")
        assert "site_github" in result["dorks"]


class TestBuildDorksForUsername:
    def test_username_dorks_count(self):
        result = dorks_recon.build_dorks_for_username("johndoe")
        assert result["type"] == "username"
        assert result["target"] == "johndoe"
        assert len(result["dorks"]) >= 7


class TestBuildDorksForName:
    def test_name_dorks_includes_linkedin(self):
        result = dorks_recon.build_dorks_for_name("John Doe")
        assert "linkedin" in result["dorks"]

    def test_name_dorks_includes_maps(self):
        result = dorks_recon.build_dorks_for_name("John Doe")
        assert "maps" in result["dorks"]


class TestBuildDorksForCompany:
    def test_company_dorks_includes_crunchbase(self):
        result = dorks_recon.build_dorks_for_company("Acme Corp")
        assert "crunchbase" in result["dorks"]


class TestBuildSensitiveDorks:
    def test_sensitive_dorks_count(self):
        result = dorks_recon.build_sensitive_dorks()
        assert result["type"] == "sensitive"
        # Should have 15+ general sensitive dorks
        assert len(result["dorks"]) >= 15

    def test_sensitive_dorks_includes_passwords(self):
        result = dorks_recon.build_sensitive_dorks()
        assert "passwords" in result["dorks"]

    def test_sensitive_dorks_includes_phpinfo(self):
        result = dorks_recon.build_sensitive_dorks()
        assert "phpinfo" in result["dorks"]


class TestRun:
    def test_run_with_domain(self):
        from root3st.config import Config
        config = Config()
        result = dorks_recon.run("example.com", "domain", config)
        assert result["type"] == "domain"

    def test_run_with_email(self):
        from root3st.config import Config
        config = Config()
        result = dorks_recon.run("test@test.com", "email", config)
        assert result["type"] == "email"

    def test_run_with_sensitive(self):
        from root3st.config import Config
        config = Config()
        result = dorks_recon.run("sensitive", "sensitive", config)
        assert result["type"] == "sensitive"

    def test_run_unknown_type(self):
        from root3st.config import Config
        config = Config()
        result = dorks_recon.run("test", "unknown_type", config)
        assert "error" in result