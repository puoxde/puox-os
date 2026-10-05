# PUOX-OS

Selbst gehostetes Dashboard für einen Markdown-Wissens-Vault (Obsidian-Stil) mit KI-Agenten.
Ein einzelner Python-Server (`server.py`, nur Standardbibliothek) liefert eine Oberfläche
(`index.html`) aus und liest bzw. schreibt den Vault, in dem der Ordner liegt.

## Funktionen

- Übersicht über Aufgaben, Projekte, Kunden und potenzielle Kunden aus dem Vault; Explorer, Volltextsuche, Backlinks, Graph
- Kalender aus ICS-Quellen plus lokale Termine (`termine.json`, `termine.txt`)
- Mail-Client für bis zu 5 IMAP/SMTP-Postfächer, Zugangsdaten per Windows-DPAPI verschlüsselt
- Matrix-Chat im Browser, Uptime-Monitoring (`uptime.txt`), optionale OPNsense-Karte über die REST-API
- Chat mit Agenten, DB-Update und Git-Commit über die Claude-Code-CLI (`claude -p`)
- Theme-Editor (Farben, Schriften, Hintergrund), Abteilungs-Map (`abteilungen.json`)
- Sicherheit: Zugangs-PIN vor jeder Anfrage, Netz-Freigabeliste (`netzzugang.json`), HTTPS mit Host-Zwang,
  Dateien mit `ki_freigabe: gesperrt` im Frontmatter bleiben aus dem KI-Kontext

## Voraussetzungen

- Windows (Mail-Verschlüsselung nutzt DPAPI) und Python 3.12
- Optional: [Claude Code](https://claude.com/claude-code) im `PATH` für Chat, DB-Update und Commit

## Einrichtung

1. Den Ordner als `97_puoxos/` in den Vault legen. Der Elternordner gilt als Vault.
2. Zertifikat und Schlüssel als `tls/fullchain.pem` und `tls/privkey.pem` ablegen (selbstsigniert reicht).
3. Hostnamen setzen: `set NAME=os.example.com` (Standard). Der Server beantwortet nur diesen Namen.
4. `netzzugang.json` anpassen (`lan`, `vpn` oder `liste`), bei Bedarf `netz-einrichten.ps1` als Administrator ausführen.
5. `start.bat` starten. Beim ersten Aufruf legt man die Zugangs-PIN fest.

Optional: ein eigenes `logo.svg` neben `server.py` legen (Anmeldeseite). Agenten-Karten kommen aus `agenten/*.md`.
Weitere Umgebungsvariablen: `PORT` (Standard 443), `PORT_HTTP` (80, nur Weiterleitung), `HOST`.
Laufzeitdaten (`secrets/`, `tls/`, Logs) stehen in `.gitignore`.

## Tests

```
python test_server.py
```
