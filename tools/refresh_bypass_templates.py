#!/usr/bin/env python3
"""Сверяет встроенные шаблоны обхода с официальными источниками."""

import argparse
import datetime
from html.parser import HTMLParser
import ipaddress
import json
from pathlib import Path
import sys
import tempfile
from urllib.request import Request, urlopen


CATALOG = Path(__file__).resolve().parents[1] / "bypass_templates.json"
SOURCE_FILES = {"steam-sdr": "valve.json", "telemost": "telemost.html"}
MAX_SOURCE_BYTES = 4 * 1024 * 1024


class TelemostTable(HTMLParser):
    def __init__(self):
        super().__init__()
        self.section = False
        self.in_table = False
        self.complete = False
        self.rows = []
        self.cell = None

    def handle_starttag(self, tag, attrs):
        if tag in ("h1", "h2", "h3", "h4", "h5", "h6"):
            self.section = dict(attrs).get("id") == "telemost"
        if self.complete or not self.section:
            return
        if tag == "table":
            self.in_table = True
        if not self.in_table:
            return
        if tag == "tr":
            self.rows.append([])
        if tag in ("td", "th"):
            self.cell = []
        if tag == "br" and self.cell is not None:
            self.cell.append(" ")

    def handle_data(self, data):
        if self.cell is not None:
            self.cell.append(data)

    def handle_endtag(self, tag):
        if tag in ("td", "th") and self.cell is not None:
            self.rows[-1].append(" ".join("".join(self.cell).split()))
            self.cell = None
        if tag == "table" and self.in_table:
            self.in_table = False
            self.complete = True


def public_ipv4(network):
    if not network.is_global or network.is_multicast or network.is_reserved:
        raise ValueError(f"Источник содержит специальный диапазон {network}")
    return str(network)


def telemost_destinations(payload):
    table = TelemostTable()
    table.feed(payload.decode("utf-8"))
    table.close()
    if not table.complete or not table.rows or table.rows[0][:3] != [
        "Ресурс", "IP-адреса", "Протокол / порты"
    ]:
        raise ValueError("Не найдена таблица адресов Телемоста")

    destinations = set()
    for row in table.rows[1:]:
        if len(row) != len(table.rows[0]):
            raise ValueError("Неожиданный формат строки таблицы Телемоста")
        # Здесь начинаются общие зависимости чата, Диска и форм.
        if row[0] == "messenger.360.yandex.ru":
            return destinations
        if not row[1]:
            continue
        for value in row[1].split(","):
            network = ipaddress.ip_network(value.strip())
            if network.version == 4:
                destinations.add(public_ipv4(network))
    raise ValueError("Не найдена граница списка адресов видеосвязи Телемоста")


def steam_destinations(payload, ports):
    config = json.loads(payload)
    if config["success"] is not True:
        raise ValueError("Valve не вернула конфигурацию SDR")

    first_port, last_port = map(int, ports.split("-"))
    destinations = set()
    for pop in config["pops"].values():
        for relay in pop.get("relays", []):
            if "ipv4" not in relay:
                continue
            first, last = relay["port_range"]
            if (type(first) is not int or type(last) is not int
                    or not first_port <= first <= last <= last_port):
                raise ValueError(f"У ретранслятора {relay['ipv4']} изменились UDP-порты")
            network = ipaddress.IPv4Network(relay["ipv4"] + "/32")
            destinations.add(public_ipv4(network))
    return destinations


def read_source(template, source_dir):
    if source_dir is not None:
        with (source_dir / SOURCE_FILES[template["id"]]).open("rb") as source:
            return source.read(MAX_SOURCE_BYTES + 1)
    request = Request(template["sources"][0], headers={"User-Agent": "xkeen-stats template refresh"})
    with urlopen(request, timeout=25) as response:
        return response.read(MAX_SOURCE_BYTES + 1)


def refresh(catalog, source_dir, updated):
    changed = False
    for template in catalog:
        template_id = template["id"]
        if template_id not in SOURCE_FILES:
            continue
        try:
            payload = read_source(template, source_dir)
            if len(payload) > MAX_SOURCE_BYTES:
                raise ValueError("Ответ источника слишком велик")
            if template_id == "telemost":
                destinations = telemost_destinations(payload)
            else:
                destinations = steam_destinations(payload, template["ports"])
            if not 1 <= len(destinations) <= 2048:
                raise ValueError("Шаблон должен содержать от 1 до 2048 IPv4-адресов и подсетей")
        except (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError) as error:
            raise ValueError(f"{template['name']}: {error}") from error

        old = set(template["destinations"])
        print(f"{template['name']}: {len(old)} → {len(destinations)}")
        for prefix, differences in (("+", destinations - old), ("-", old - destinations)):
            for address in sorted(differences):
                print(f"  {prefix} {address}")
        if destinations != old:
            template["destinations"] = sorted(destinations)
            template["updated"] = updated
            changed = True

    if sum(len(template["destinations"]) for template in catalog) > 4096:
        raise ValueError("Суммарное число адресов шаблонов превысило 4096")
    return changed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="Записать показанные изменения в каталог")
    parser.add_argument("--source-dir", type=Path, help="Взять valve.json и telemost.html из локальной папки")
    args = parser.parse_args()

    try:
        original = CATALOG.read_bytes()
        catalog = json.loads(original)
        changed = refresh(catalog, args.source_dir, datetime.date.today().isoformat())
        if changed and args.write:
            payload = json.dumps(catalog, ensure_ascii=False, indent=2) + "\n"
            with tempfile.NamedTemporaryFile(dir=CATALOG.parent, delete=False) as output:
                temporary = Path(output.name)
            try:
                temporary.write_bytes(payload.encode("utf-8"))
                if CATALOG.read_bytes() != original:
                    raise ValueError("Каталог изменился во время сверки")
                temporary.replace(CATALOG)
            finally:
                temporary.unlink(missing_ok=True)
            print(f"Записан {CATALOG.name}")
        elif changed:
            print("Для записи изменений запустите команду с --write.")
        else:
            print("Шаблоны совпадают с источниками.")
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
