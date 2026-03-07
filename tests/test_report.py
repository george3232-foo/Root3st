"""Tests for root3st.report module."""

import json
import tempfile

from root3st.report import save_html, save_json


class TestSaveJson:
    def test_creates_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            results = {"target": "test", "type": "ip", "data": "hello"}
            path = save_json(results, tmpdir)
            assert path.exists()
            content = json.loads(path.read_text())
            assert content["target"] == "test"


class TestSaveHtml:
    def test_creates_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            results = {"target": "test", "type": "domain", "data": "world"}
            path = save_html(results, tmpdir)
            assert path.exists()
            html = path.read_text()
            assert "Root3st" in html
            assert "test" in html
