import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import refresh_bypass_templates as refresh


TELEMOST = """
<h3 id="disk">Диск</h3><table><tr><td>Диск</td><td>1.1.1.1</td></tr></table>
<h3 id="telemost">Телемост</h3>
<table>
  <tr><th>Ресурс</th><th>IP-адреса</th><th>Протокол / порты</th></tr>
  <tr><td></td><td><code>37.140.142.0/24</code>, <code>2a02:6b8::/29</code></td><td>UDP</td></tr>
  <tr><td><code>messenger.360.yandex.ru</code></td><td>77.88.21.212</td><td>HTTPS</td></tr>
</table>
"""


class RefreshTests(unittest.TestCase):
    def invoke(self, directory, write=False):
        catalog = directory / "bypass_templates.json"
        args = ["refresh", "--source-dir", str(directory)]
        if write:
            args.append("--write")
        output = io.StringIO()
        with patch.object(refresh, "CATALOG", catalog), patch.object(sys, "argv", args):
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                result = refresh.main()
        return result, output.getvalue()

    def test_review_then_write_selected_ipv4(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            catalog = directory / "bypass_templates.json"
            templates = json.loads(refresh.CATALOG.read_bytes())
            steam = next(item for item in templates if item["id"] == "steam-sdr")
            steam["destinations"] = ["9.9.9.9/32"]
            original = json.dumps(templates, ensure_ascii=False).encode("utf-8")
            catalog.write_bytes(original)
            (directory / "telemost.html").write_text(TELEMOST, encoding="utf-8")
            valve = {"success": True, "pops": {"one": {"relays": [
                {"ipv4": "8.8.8.8", "port_range": [27015, 27060]},
                {"ipv6": "2001:4860::1", "port_range": [27015, 27060]},
            ]}}}
            (directory / "valve.json").write_text(json.dumps(valve), encoding="utf-8")

            status, output = self.invoke(directory)
            self.assertEqual(status, 0, output)
            self.assertIn("+ 8.8.8.8/32", output)
            self.assertIn("- 9.9.9.9/32", output)
            self.assertEqual(catalog.read_bytes(), original)

            status, output = self.invoke(directory, write=True)
            self.assertEqual(status, 0, output)
            before = {item["id"]: item for item in json.loads(original)}
            after = {item["id"]: item for item in json.loads(catalog.read_bytes())}
            self.assertEqual(after["telemost"]["destinations"], ["37.140.142.0/24"])
            self.assertEqual(after["steam-sdr"]["destinations"], ["8.8.8.8/32"])
            self.assertEqual(after["steam-sdr"]["ports"], before["steam-sdr"]["ports"])
            self.assertEqual(after["steam-sdr"]["scope"], "devices")
            self.assertEqual(after["kinopoisk"], before["kinopoisk"])
            self.assertEqual(after["vk"], before["vk"])
            updated = catalog.read_bytes()
            status, output = self.invoke(directory, write=True)
            self.assertEqual(status, 0, output)
            self.assertEqual(catalog.read_bytes(), updated)

    def test_port_change_does_not_write_partial_update(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            catalog = directory / "bypass_templates.json"
            original = refresh.CATALOG.read_bytes()
            catalog.write_bytes(original)
            (directory / "telemost.html").write_text(TELEMOST, encoding="utf-8")
            valve = {"success": True, "pops": {"one": {"relays": [
                {"ipv4": "8.8.8.8", "port_range": [27015, 27141]},
            ]}}}
            (directory / "valve.json").write_text(json.dumps(valve), encoding="utf-8")

            status, output = self.invoke(directory, write=True)
            self.assertEqual(status, 1, output)
            self.assertIn("изменились UDP-порты", output)
            self.assertEqual(catalog.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
