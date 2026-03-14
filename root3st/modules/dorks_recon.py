"""Google Dorks Builder module.

Generates advanced Google search dorks for OSINT reconnaissance across
various target types including emails, domains, files, sensitive data, etc.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote_plus

from root3st.config import Config


def build_dorks_for_email(email: str) -> dict[str, Any]:
    """Generate Google dorks for an email address."""
    encoded = quote_plus(email)
    return {
        "type": "email",
        "target": email,
        "dorks": {
            "general": f"https://www.google.com/search?q=%22{encoded}%22",
            "site_github": f"https://www.google.com/search?q=site%3Agithub.com+\"{email}\"",
            "site_linkedin": f"https://www.google.com/search?q=site%3Alinkedin.com+\"{email}\"",
            "site_twitter": f"https://www.google.com/search?q=site%3Atwitter.com+\"{email}\"",
            "site_facebook": f"https://www.google.com/search?q=site%3Afacebook.com+\"{email}\"",
            "site_stackoverflow": f"https://www.google.com/search?q=site%3Astackoverflow.com+\"{email}\"",
            "pastebin": f"https://www.google.com/search?q=\"{email}\"+site%3Apastebin.com",
            "pdf": f"https://www.google.com/search?q=\"{email}\"+filetype%3Apdf",
            "exposed_docs": f"https://www.google.com/search?q=\"{email}\"+filetype%3Adoc+OR+filetype%3Adocx+OR+filetype%3Apdf",
        },
    }


def build_dorks_for_domain(domain: str) -> dict[str, Any]:
    """Generate Google dorks for a domain."""
    return {
        "type": "domain",
        "target": domain,
        "dorks": {
            "site": f"https://www.google.com/search?q=site%3A{domain}",
            "subdomains": f"https://www.google.com/search?q=site%3A*.{domain}",
            "login_pages": f"https://www.google.com/search?q=site%3A{domain}+login+OR+signin+OR+admin",
            "pdf_files": f"https://www.google.com/search?q=site%3A{domain}+filetype%3Apdf",
            "excel_files": f"https://www.google.com/search?q=site%3A{domain}+filetype%3Axls+OR+filetype%3Axlsx",
            "word_docs": f"https://www.google.com/search?q=site%3A{domain}+filetype%3Adoc+OR+filetype%3Adocx",
            "config_files": f"https://www.google.com/search?q=site%3A{domain}+filetype%3Ayaml+OR+filetype%3Ayml+OR+filetype%3Ajson",
            "backup_files": f"https://www.google.com/search?q=site%3A{domain}+filetype%3Abak+OR+filetype%3Atar+OR+filetype%3Agz",
            "sql_dump": f"https://www.google.com/search?q=site%3A{domain}+filetype%3Asql+OR+filetype%3Adb",
            "phpinfo": f"https://www.google.com/search?q=site%3A{domain}+phpinfo.php",
            "wordpress": f"https://www.google.com/search?q=site%3A{domain}+wordpress+OR+wp-content",
            "s3_bucket": f"https://www.google.com/search?q=site%3As3.amazonaws.com+{domain}",
            "dir_listing": f"https://www.google.com/search?q=site%3A{domain}+intitle%3Aindex.of",
            "sensitive_words": f"https://www.google.com/search?q=site%3A{domain}+password+OR+secret+OR+confidential",
            "api_keys": f"https://www.google.com/search?q=site%3A{domain}+api_key+OR+apikey+OR+secret",
            "cve_search": f"https://www.google.com/search?q={domain}+CVE",
            "archived": f"https://web.archive.org/web/*/{domain}",
        },
    }


def build_dorks_for_username(username: str) -> dict[str, Any]:
    """Generate Google dorks for a username."""
    encoded = quote_plus(username)
    return {
        "type": "username",
        "target": username,
        "dorks": {
            "general": f"https://www.google.com/search?q=%22{encoded}%22",
            "github": f"https://www.google.com/search?q=site%3Agithub.com+\"{username}\"",
            "twitter": f"https://www.google.com/search?q=site%3Atwitter.com+\"{username}\"",
            "instagram": f"https://www.google.com/search?q=site%3Ainstagram.com+\"{username}\"",
            "reddit": f"https://www.google.com/search?q=site%3Areddit.com+\"u/{username}\"",
            "youtube": f"https://www.google.com/search?q=site%3Ayoutube.com+\"{username}\"",
            "pastebin": f"https://www.google.com/search?q=\"{username}\"+site%3Apastebin.com",
            "gist_github": f"https://www.google.com/search?q=\"{username}\"+site%3Agist.github.com",
        },
    }


def build_dorks_for_phone(phone: str) -> dict[str, Any]:
    """Generate Google dorks for a phone number."""
    # Remove special characters for search
    clean_phone = quote_plus(phone.replace("+", "").replace("-", "").replace(" ", ""))
    return {
        "type": "phone",
        "target": phone,
        "dorks": {
            "general": f"https://www.google.com/search?q={clean_phone}",
            "whatsapp": f"https://www.google.com/search?q={clean_phone}+whatsapp",
            "telegram": f"https://www.google.com/search?q={clean_phone}+telegram",
            "facebook": f"https://www.google.com/search?q=\"{phone}\"+site%3Afacebook.com",
            "linkedin": f"https://www.google.com/search?q=\"{phone}\"+site%3Alinkedin.com",
        },
    }


def build_dorks_for_name(name: str) -> dict[str, Any]:
    """Generate Google dorks for a person's name."""
    encoded = quote_plus(name)
    return {
        "type": "name",
        "target": name,
        "dorks": {
            "general": f"https://www.google.com/search?q=%22{encoded}%22",
            "linkedin": f"https://www.google.com/search?q=site%3Alinkedin.com+\"{name}\"",
            "facebook": f"https://www.google.com/search?q=site%3Afacebook.com+\"{name}\"",
            "twitter": f"https://www.google.com/search?q=site%3Atwitter.com+\"{name}\"",
            "instagram": f"https://www.google.com/search?q=site%3Ainstagram.com+\"{name}\"",
            "github": f"https://www.google.com/search?q=site%3Agithub.com+\"{name}\"",
            "news": f"https://www.google.com/search?q=%22{encoded}%22&tbm=nws",
            "images": f"https://www.google.com/search?q=%22{encoded}%22&tbm=isch",
            "maps": f"https://www.google.com/maps/search/{encoded}",
            "resume": f"https://www.google.com/search?q=\"{name}\"+resume+OR+CV+OR+curriculum",
        },
    }


def build_dorks_for_company(company: str) -> dict[str, Any]:
    """Generate Google dorks for a company name."""
    encoded = quote_plus(company)
    return {
        "type": "company",
        "target": company,
        "dorks": {
            "general": f"https://www.google.com/search?q=%22{encoded}%22",
            "linkedin": f"https://www.google.com/search?q=site%3Alinkedin.com+\"{company}\"",
            "crunchbase": f"https://www.google.com/search?q=\"{company}\"+site%3Acrunchbase.com",
            "glassdoor": f"https://www.google.com/search?q=\"{company}\"+site%3Aglassdoor.com",
            "indeed": f"https://www.google.com/search?q=\"{company}\"+site%3Aindeed.com",
            "news": f"https://www.google.com/search?q=\"{company}\"&tbm=nws",
            "pdf_reports": f"https://www.google.com/search?q=\"{company}\"+filetype%3Apdf",
            "emails": f"https://www.google.com/search?q=\"{company}\"+email+OR+@",
        },
    }


def build_sensitive_dorks() -> dict[str, Any]:
    """Generate general dorks for finding sensitive data."""
    return {
        "type": "sensitive",
        "target": "general",
        "dorks": {
            "passwords": "https://www.google.com/search?q=filetype%3Atxt+password",
            "email_lists": "https://www.google.com/search?q=filetype%3Axls+email",
            "database_dumps": "https://www.google.com/search?q=filetype%3Asql+\"INSERT+INTO\"",
            "config_exposed": "https://www.google.com/search?q=filetype%3Aenv+OR+config+OR+configuration",
            "private_keys": "https://www.google.com/search?q=filetype%3Apem+OR+filetype%3Akey",
            "backup_files": "https://www.google.com/search?q=filetype%3Abak+OR+filetype%3Abackup",
            "excel_data": "https://www.google.com/search?q=filetype%3Axlsx+OR+filetype%3Axls+OR+filetype%3Acsv",
            "pdf_sensitive": "https://www.google.com/search?q=filetype%3Apdf+confidential+OR+secret+OR+internal",
            "login_pages": "https://www.google.com/search?q=login+OR+signin+OR+admin+intitle%3Alogin",
            "wordpress_config": "https://www.google.com/search?q=wp-config.php+filetype%3Aphp",
            "aws_keys": "https://www.google.com/search?q=AKIA+OR+AWSSecretKey",
            "google_api": "https://www.google.com/search?q=AIza+OR+google-api",
            "jwt_tokens": "https://www.google.com/search?q=eyJhbGciOiJIUzI1NiJ9",
            "phpinfo": "https://www.google.com/search?q=phpinfo.php",
            "directory_listing": "https://www.google.com/search?q=intitle%3Aindex.of",
        },
    }


def run(target: str, target_type: str, config: Config) -> dict[str, Any]:
    """Execute Google dorks builder based on target type.

    Args:
        target: The search target (email, domain, username, etc.)
        target_type: Type of target (email, domain, username, phone, name, company, sensitive)
        config: Configuration object

    Returns:
        Dictionary containing generated dork URLs
    """
    if target_type == "email":
        return build_dorks_for_email(target)
    elif target_type == "domain":
        return build_dorks_for_domain(target)
    elif target_type == "username":
        return build_dorks_for_username(target)
    elif target_type == "phone":
        return build_dorks_for_phone(target)
    elif target_type == "name":
        return build_dorks_for_name(target)
    elif target_type == "company":
        return build_dorks_for_company(target)
    elif target_type == "sensitive":
        return build_sensitive_dorks()
    else:
        return {"error": f"Unknown target type: {target_type}"}
