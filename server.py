#!/usr/bin/env python3
"""PUOX-OS-Dashboard. Start: start.bat | https://os.example.com (ausschliesslich dieser Name)
Daten: puox.exe db-check --manifest (respektiert Sperrzonen fuer LLM-Kontext).
Anzeige gesperrter Dateien (full=1) bleibt LOKAL (Datei -> Browser, keine Cloud-KI).
Schreibpfade: Aufgaben, 02_kunden (neu/bearbeiten), potenzielle Kunden. Chat/db-update: claude -p.

Netzzugang: horcht auf allen Schnittstellen, laesst aber nur die in netzzugang.json erlaubten
Netze durch UND verlangt vor jeder Anfrage eine Zugangs-PIN (auch lokal).
Davor steht der Host-Zwang: nur os.example.com wird bedient, alles andere 421."""
import calendar, glob as globmod, json, os, re, shutil, ssl, subprocess, sys, tempfile, threading, time, uuid
import urllib.request, urllib.error, webbrowser
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, quote, unquote
from http.cookies import SimpleCookie

BASE  = os.path.dirname(os.path.abspath(__file__))
VAULT = os.path.dirname(BASE)
# Genau EINE gueltige Adresse. Alles andere -- fruehere Namen, localhost,
# jeder IP-Zugriff -- wird mit 421 abgewiesen; siehe host_ok(). Ueber den Namen laeuft das
# selbstsignierte Zertifikat, damit die PIN nicht mehr im Klartext durchs Netz geht.
NAME  = os.environ.get('NAME', 'os.example.com')
# 443 statt 80: Windows verlangt fuer Ports < 1024 keine Administratorrechte (anders als Unix).
PORT      = int(os.environ.get('PORT', 443))
PORT_HTTP = int(os.environ.get('PORT_HTTP', 80))   # nur Weiterleitung auf https, best effort
HOST  = os.environ.get('HOST', '0.0.0.0')
# NICHT nach 97_puoxos/secrets/ -- die Sperrzone fuer Zugangsdaten bleibt fuer den Server tabu,
# eine eigene .gitignore-Zeile haelt den
# privaten Schluessel trotzdem aus dem Repo.
TLS_DIR   = os.path.join(BASE, 'tls')
TLS_CERT  = os.path.join(TLS_DIR, 'fullchain.pem')
TLS_KEY   = os.path.join(TLS_DIR, 'privkey.pem')
GESPERRT = re.compile(r'^ki_freigabe:\s*gesperrt', re.M)
# CLI liegt oft in ~/.local/bin, das nicht in jedem Prozess-PATH steckt
CLAUDE = shutil.which('claude') or os.path.join(os.path.expanduser('~'), '.local', 'bin', 'claude.exe')
# Werkzeuge (db-check, backup) liegen als Go-Binary vor.
PUOX = os.path.join(VAULT, '_tools', 'skripte', 'bin', 'puox.exe')

def run(args, cwd=VAULT, timeout=None):
    p = subprocess.run(args, capture_output=True, text=True, encoding='utf-8', errors='replace', cwd=cwd, timeout=timeout)
    return (p.stdout or ''), (p.stderr or ''), p.returncode

def head_of(path, n=2000):
    with open(path, encoding='utf-8', errors='replace') as fh:
        return fh.read(n)

def write_file(full, text, roh=None):
    """roh = fertige Bytes (Bild-Upload); sonst wird text als UTF-8 geschrieben.
    Atomar: erst eine Temp-Datei im selben Ordner, Groesse pruefen, dann os.replace. Bricht
    das Schreiben ab (Platte voll, Ausnahme), bleibt das Original unberuehrt statt leer."""
    data = roh if roh is not None else text.encode('utf-8')
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(full), prefix='.' + os.path.basename(full) + '.', suffix='.tmp')
    try:
        with os.fdopen(fd, 'wb') as fh:
            fh.write(data)
        if os.path.getsize(tmp) != len(data):  # Mount-Truncation-Wache
            return {'error': 'Schreib-Verifikation fehlgeschlagen — Datei pruefen!'}
        for versuch in range(20):   # Windows: ein gerade lesender Thread sperrt das Ersetzen kurz (WinError 5)
            try:
                os.replace(tmp, full)
                break
            except PermissionError:
                if versuch == 19:
                    raise
                time.sleep(0.05)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return {'ok': True}

def vault_md(rel):
    full = os.path.realpath(os.path.join(VAULT, rel))
    # Mit Trenner vergleichen: sonst gaelte ein Nachbarordner wie C:\vault-alt als "im Vault"
    return full if full.startswith(os.path.join(os.path.realpath(VAULT), '')) and full.endswith('.md') else None

DATEI_MAX = 2000000   # Zeichen; laengere Dateien liefert api_file gekuerzt und nur zum Lesen

# ---------- Lesen ----------
def api_manifest():
    out, err, rc = run([PUOX, 'db-check', '--manifest'])
    if rc != 0 or not out.strip():   # sonst wirft json.loads ein nichtssagendes "Expecting value"
        raise RuntimeError('puox.exe db-check --manifest: rc %s %s' % (rc, err.strip()[:300]))
    return json.loads(out)

# Ordner, die im Explorer nichts verloren haben: Werkzeug-Innereien und die Sperrzone mit den
# Zugaengen. Punkt-Ordner (.git, .obsidian, .claude) fallen ueber die Namenspruefung mit weg.
# Vergleich klein: auch eine Gross-Schreibweise (`Secrets`) faellt darunter, sonst waeren
# Dateinamen, Groesse und Datum der Zugangsdateien im Explorer sichtbar.
EXPLORER_AUS = {'__pycache__', 'node_modules', 'secrets', '_tools'}
def api_explorer():
    """Vollstaendige Dateiliste des Vaults -- nur Pfad, Groesse und Datum, KEIN Inhalt.
    Damit bleibt die Sperrzonen-Regel gewahrt: gesperrte Zonen werden nicht gelesen, nur aufgezaehlt."""
    out = []
    for wurzel, dirs, dateien in os.walk(VAULT):
        dirs[:] = sorted(d for d in dirs if d.lower() not in EXPLORER_AUS and not d.startswith('.'))
        for f in dateien:
            if f.startswith('.'):
                continue
            voll = os.path.join(wurzel, f)
            try:
                st = os.stat(voll)
            except OSError:
                continue
            out.append({'path': os.path.relpath(voll, VAULT).replace('\\', '/'),
                        'bytes': st.st_size, 'mtime': int(st.st_mtime)})
    out.sort(key=lambda x: x['path'].lower())
    return {'dateien': out, 'anzahl': len(out), 'bytes': sum(x['bytes'] for x in out)}

def api_dbcheck():
    out, err, _ = run([PUOX, 'db-check'])
    text = out or err   # rc ist auch bei Befunden 0 -- ausgewertet wird der Text
    return {'ok': '[OK] PUOX-DB konsistent' in text, 'findings': text.count('[X]'), 'output': text}

def age_h(path):
    return round((time.time() - os.path.getmtime(path)) / 3600, 1)

def api_monitoring():
    offen_dir = os.path.join(VAULT, '11_aktualisierungen', 'offen')
    offen = [{'name': f, 'alter_h': age_h(os.path.join(offen_dir, f))}
             for f in sorted(os.listdir(offen_dir)) if f.endswith('.md')] if os.path.isdir(offen_dir) else []
    bdir = os.path.join(VAULT, '_backups')
    zips = sorted((f for f in os.listdir(bdir) if f.endswith('.zip')),
                  key=lambda f: os.path.getmtime(os.path.join(bdir, f))) if os.path.isdir(bdir) else []
    backup = {'name': zips[-1], 'alter_h': age_h(os.path.join(bdir, zips[-1]))} if zips else None
    out, _, _ = run(['git', 'status', '--porcelain'])
    return {'snapshots': offen, 'backup': backup, 'backup_auto': BAK,
            'git': len([l for l in out.splitlines() if l.strip()])}

def api_abteilungen():
    """Abteilungen der Map (97_puoxos/abteilungen.json). Einzige Quelle fuer Namen, Farbe,
    Piktogramm, Beschreibung, Zustaendigkeiten samt Stationen und Agenten-Zuordnung."""
    p = os.path.join(BASE, 'abteilungen.json')
    if not os.path.isfile(p):
        return {'abteilungen': [], 'error': 'abteilungen.json fehlt'}
    try:
        return {'abteilungen': json.load(open(p, encoding='utf-8')).get('abteilungen', [])}
    except Exception as e:
        return {'abteilungen': [], 'error': 'abteilungen.json ungueltig: %s' % e}

def api_config():
    cfg = os.path.join(BASE, 'dashboard.json')
    default = {'ziel_eur': 100000, 'usage_limit_pct': None, 'kalender_ics': '', 'kalender_extern': ''}
    if not os.path.isfile(cfg):
        json.dump(default, open(cfg, 'w', encoding='utf-8'), indent=1)
    d = dict(default)
    try:
        d.update(json.load(open(cfg, encoding='utf-8')))
    except Exception as e:
        d['config_error'] = 'dashboard.json ungueltig: %s' % e
    d['usage_tokens'] = usage_tokens()
    return d

# ---------- Theme + Einstellungen (Farben, Menue, Schrift, Zeit, Hauptquellen) ----------
THEME_FILE = os.path.join(BASE, 'theme.json')
THEME_DEFAULT = {'bg': '#131311', 'panel': '#1b1b18', 'line': '#2b2b26', 'mint': '#21F1A8',
                  'mint2': '#66B8FF', 'cream': '#E9E3D5', 'dim': '#8f8f83', 'err': '#FF6B6B',
                  'amber': '#d8b35a'}
# Nicht-Farben stehen in derselben Datei -- jede mit eigener Validierung (Whitelist/Bereich/Freitext)
UI_DEFAULT = {
    'font_head': 'system-ui',   # Ueberschriften
    'font_body': '',            # leer = erbt font_head (bewusst: leer heisst "wie Ueberschrift")
    'fs_body': 14,              # 8..32
    'fs_head': 18,              # 12..36
    'menue': 'puox',            # puox | burger
    'burger_pos': 'links',      # links | rechts | oben  (nur bei menue=burger)
    'burger_auto': True,        # True = schliesst beim Verlassen mit der Maus, False = Klick-Umschalter
    'hintergrund': 'puox',      # puox (Weltall) | bild
    'zeitzone': 'Europe/Berlin',
    'zeitformat': 24,           # 24 | 12
    'region': 'de-DE',          # Datumsformat; Mail uebernimmt es von hier
    'mail_poll_stunden': 24,    # automatischer Mail-Abgleich (fruher je Postfach)
    'hauptkalender': '',        # '' = lokal, sonst Kalender-Id aus kalender.json
    'hauptpostfach': '',        # '' = erstes Postfach, sonst account-Id
}
REGIONEN = ['de-DE', 'en-GB', 'en-US', 'fr-FR', 'it-IT', 'es-ES', 'nl-NL', 'pl-PL']
FONTS = ['system-ui', 'Segoe UI', 'Inter', 'Georgia', 'Consolas', 'Cambria', 'Verdana', 'Tahoma',
         'Trebuchet MS', 'Palatino Linotype', 'Courier New', 'Impact']
HEX_RE = re.compile(r'\A#[0-9a-fA-F]{6}\Z')
BG_DIR = os.path.join(BASE, 'hintergrund')   # Ordnernamen klein (Konvention)
BG_EXT = {'image/png': '.png', 'image/jpeg': '.jpg', 'image/webp': '.webp', 'image/gif': '.gif'}
# ---------- Eigene Schriften ----------
# Liegen als Datei in 97_puoxos/schriften und werden ueber /schrift/<datei> ausgeliefert; die
# Oberflaeche baut daraus @font-face. Das ist KEINE Windows-Installation -- die Schrift gilt nur
# in PUOX-OS, dafuer ohne Administratorrechte und auf jedem Geraet im Netz gleich.
SCHRIFT_DIR = os.path.join(BASE, 'schriften')
SCHRIFT_MIME = {'.ttf': 'font/ttf', '.otf': 'font/otf', '.woff': 'font/woff', '.woff2': 'font/woff2'}
SCHRIFT_NAME = re.compile(r'\A[A-Za-z0-9 _.\-]{1,60}\Z')
SCHRIFT_MAX = 8 * 1024 * 1024

def _clamp_int(v, lo, hi, fallback):
    try:
        return max(lo, min(hi, int(v)))
    except (TypeError, ValueError):
        return fallback

def _bg_datei():
    """Der zuletzt hochgeladene Hintergrund -- es gibt bewusst immer nur einen."""
    for e in BG_EXT.values():
        p = os.path.join(BG_DIR, 'hintergrund' + e)
        if os.path.isfile(p):
            return p
    return None

def api_theme():
    out = dict(THEME_DEFAULT)
    out.update(UI_DEFAULT)
    gespeichert = {}
    if os.path.isfile(THEME_FILE):
        try:
            gespeichert = json.load(open(THEME_FILE, encoding='utf-8'))
        except Exception:
            gespeichert = {}
    out.update({k: v for k, v in gespeichert.items()
                if k in THEME_DEFAULT and isinstance(v, str) and HEX_RE.match(v)})
    # Altbestand: bis 2026-08 hiessen die Felder font/fontsize und galten fuer alles
    if gespeichert.get('font') in FONTS:
        out['font_head'] = gespeichert['font']
    if 'fontsize' in gespeichert:
        out['fs_body'] = _clamp_int(gespeichert['fontsize'], 8, 32, out['fs_body'])
    erlaubt = FONTS + schrift_namen()   # eigene, in PUOX-OS installierte Schriften zaehlen mit
    for k in ('font_head', 'font_body'):
        if gespeichert.get(k) in erlaubt or gespeichert.get(k) == '':
            out[k] = gespeichert[k]
    out['fs_body'] = _clamp_int(gespeichert.get('fs_body', out['fs_body']), 8, 32, out['fs_body'])
    out['fs_head'] = _clamp_int(gespeichert.get('fs_head', out['fs_head']), 12, 36, out['fs_head'])
    if gespeichert.get('menue') in ('puox', 'burger'):
        out['menue'] = gespeichert['menue']
    if gespeichert.get('burger_pos') in ('links', 'rechts', 'oben'):
        out['burger_pos'] = gespeichert['burger_pos']
    out['burger_auto'] = bool(gespeichert.get('burger_auto', out['burger_auto']))
    if gespeichert.get('hintergrund') in ('puox', 'bild'):
        out['hintergrund'] = gespeichert['hintergrund']
    if isinstance(gespeichert.get('zeitzone'), str) and re.match(r'\A[A-Za-z_+\-/]{1,40}\Z', gespeichert['zeitzone']):
        out['zeitzone'] = gespeichert['zeitzone']
    out['zeitformat'] = 12 if str(gespeichert.get('zeitformat')) == '12' else 24
    if gespeichert.get('region') in REGIONEN:
        out['region'] = gespeichert['region']
    out['mail_poll_stunden'] = _clamp_int(gespeichert.get('mail_poll_stunden'), 1, 168, 24)
    for k in ('hauptkalender', 'hauptpostfach'):
        if isinstance(gespeichert.get(k), str):
            out[k] = gespeichert[k][:80]
    out['hat_hintergrundbild'] = _bg_datei() is not None
    return out

def api_theme_save(d):
    out = {k: d.get(k) for k in THEME_DEFAULT if isinstance(d.get(k), str) and HEX_RE.match(d.get(k) or '')}
    erlaubt = FONTS + schrift_namen()
    for k in ('font_head', 'font_body'):
        if d.get(k) in erlaubt or d.get(k) == '':
            out[k] = d[k]
    out['fs_body'] = _clamp_int(d.get('fs_body'), 8, 32, UI_DEFAULT['fs_body'])
    out['fs_head'] = _clamp_int(d.get('fs_head'), 12, 36, UI_DEFAULT['fs_head'])
    if d.get('menue') in ('puox', 'burger'):
        out['menue'] = d['menue']
    if d.get('burger_pos') in ('links', 'rechts', 'oben'):
        out['burger_pos'] = d['burger_pos']
    out['burger_auto'] = bool(d.get('burger_auto', True))
    if d.get('hintergrund') in ('puox', 'bild'):
        out['hintergrund'] = d['hintergrund']
    if isinstance(d.get('zeitzone'), str) and re.match(r'\A[A-Za-z_+\-/]{1,40}\Z', d['zeitzone']):
        out['zeitzone'] = d['zeitzone']
    out['zeitformat'] = 12 if str(d.get('zeitformat')) == '12' else 24
    if d.get('region') in REGIONEN:
        out['region'] = d['region']
    out['mail_poll_stunden'] = _clamp_int(d.get('mail_poll_stunden'), 1, 168, 24)
    for k in ('hauptkalender', 'hauptpostfach'):
        if isinstance(d.get(k), str):
            out[k] = d[k][:80]
    return write_file(THEME_FILE, json.dumps(out, indent=1, ensure_ascii=False))

def api_hintergrund_save(d):
    """Ein Bild, base64 aus dem Datei-Dialog. Das alte wird geloescht -- 'nur bis ein anderes gewaehlt wird'."""
    import base64
    mime = (d.get('mime') or '').split(';')[0].strip().lower()
    if mime not in BG_EXT:
        return {'error': 'Nur PNG, JPEG, WebP oder GIF'}
    try:
        roh = base64.b64decode(d.get('data') or '', validate=True)
    except Exception:
        return {'error': 'Bilddaten unlesbar'}
    if not roh or len(roh) > 12 * 1024 * 1024:
        return {'error': 'Bild fehlt oder groesser als 12 MB'}
    os.makedirs(BG_DIR, exist_ok=True)
    for alt in BG_EXT.values():          # immer nur ein Hintergrund
        p = os.path.join(BG_DIR, 'hintergrund' + alt)
        if os.path.isfile(p):
            os.remove(p)
    r = write_file(os.path.join(BG_DIR, 'hintergrund' + BG_EXT[mime]), None, roh)
    return r if 'error' in r else {'ok': True, 'v': int(time.time())}

def api_hintergrund_remove(d):
    for e in BG_EXT.values():
        p = os.path.join(BG_DIR, 'hintergrund' + e)
        if os.path.isfile(p):
            os.remove(p)
    return {'ok': True}

def schriften():
    """Installierte Schriften als [{name, datei, bytes}] -- name ist der Dateiname ohne Endung
    und zugleich die font-family, unter der die Oberflaeche sie anspricht."""
    if not os.path.isdir(SCHRIFT_DIR):
        return []
    out = []
    for f in sorted(os.listdir(SCHRIFT_DIR)):
        stamm, endung = os.path.splitext(f)
        if endung.lower() not in SCHRIFT_MIME or not SCHRIFT_NAME.match(stamm):
            continue
        out.append({'name': stamm, 'datei': f, 'bytes': os.path.getsize(os.path.join(SCHRIFT_DIR, f))})
    return out

def schrift_namen():
    return [s['name'] for s in schriften()]

def schrift_datei(datei):
    """Pfad zur Schriftdatei oder None. basename gegen Pfadtricks, Whitelist gegen alles andere."""
    datei = os.path.basename(datei or '')
    stamm, endung = os.path.splitext(datei)
    if endung.lower() not in SCHRIFT_MIME or not SCHRIFT_NAME.match(stamm):
        return None
    p = os.path.join(SCHRIFT_DIR, datei)
    return p if os.path.isfile(p) else None

def api_schriften():
    return {'schriften': schriften()}

def api_schrift_save(d):
    import base64
    datei = os.path.basename((d.get('name') or '').strip())
    stamm, endung = os.path.splitext(datei)
    if endung.lower() not in SCHRIFT_MIME:
        return {'error': 'Nur TTF, OTF, WOFF oder WOFF2'}
    if not SCHRIFT_NAME.match(stamm):
        return {'error': 'Dateiname nur mit Buchstaben, Ziffern, Leerzeichen, Punkt, - und _'}
    try:
        roh = base64.b64decode(d.get('data') or '', validate=True)
    except Exception:
        return {'error': 'Schriftdaten unlesbar'}
    if not roh or len(roh) > SCHRIFT_MAX:
        return {'error': 'Datei fehlt oder groesser als 8 MB'}
    os.makedirs(SCHRIFT_DIR, exist_ok=True)
    r = write_file(os.path.join(SCHRIFT_DIR, stamm + endung.lower()), None, roh)
    return r if 'error' in r else {'ok': True, 'name': stamm}

def api_schrift_remove(d):
    p = schrift_datei(d.get('datei'))
    if not p:
        return {'error': 'Schrift nicht gefunden'}
    os.remove(p)
    # api_theme() faellt bei einer entfernten Schrift von sich aus auf die Voreinstellung zurueck.
    # Einmal zurueckschreiben, damit auch in theme.json kein toter Schriftname stehen bleibt.
    api_theme_save(api_theme())
    return {'ok': True}

# ---------- Backlinks (Wikilink-Index fuer die Datei-Ansicht im Panel) ----------
# Sperrzonen werden NICHT durchsucht (erkannt an der Markierung, nicht am Ordner): jede Datei
# mit `ki_freigabe: gesperrt`. Nur Pfade verlassen den Server, nie Dateiinhalt.
BL_CACHE = {'ts': 0, 'idx': None, 'skip': 0}
LINK_RE = re.compile(r'\[\[([^\]|#]+)')

def _backlink_index():
    if BL_CACHE['idx'] is not None and time.time() - BL_CACHE['ts'] < 120:
        return BL_CACHE['idx'], BL_CACHE['skip']
    idx, skip = {}, 0
    for root, dirs, files in os.walk(VAULT):
        dirs[:] = [x for x in dirs if not x.startswith('.')
                   and x not in ('node_modules', '_backups', 'Backups', '__pycache__')]
        for fn in files:
            if not fn.endswith('.md'):
                continue
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, VAULT).replace('\\', '/')
            if rel.startswith('02_kunden/') and GESPERRT.search(head_of(full, 2000)):  # Kundenblaetter; Projektordner lesbar
                skip += 1
                continue
            try:
                with open(full, encoding='utf-8', errors='replace') as fh:
                    text = fh.read(200000)
            except OSError:
                continue
            if GESPERRT.search(text[:2000]):
                skip += 1
                continue
            for m in LINK_RE.finditer(text):
                idx.setdefault(m.group(1).strip().lower(), set()).add(rel)
    BL_CACHE.update({'ts': time.time(), 'idx': idx, 'skip': skip})
    return idx, skip

def api_backlinks(rel):
    base = os.path.basename(rel or '')
    name = (base[:-3] if base.endswith('.md') else base).lower()
    if not name:
        return {'links': [], 'uebersprungen': 0}
    idx, skip = _backlink_index()
    return {'links': sorted(p for p in idx.get(name, ()) if p != rel), 'uebersprungen': skip}

def api_graph():
    """Der echte Wikilink-Graph fuer die Map: Knoten = Dateien, Kanten = [[Verweise]].

    Grenze: Dateien mit `ki_freigabe: gesperrt` werden nicht
    gelesen. Sie erscheinen als Knoten und man sieht Kanten, die AUF sie zeigen -- aber keine, die
    VON ihnen ausgehen. `uebersprungen` nennt die Zahl, damit das in der Oberflaeche sichtbar ist."""
    idx, skip = _backlink_index()
    manifest = api_manifest()
    dateien = manifest.get('files', [])
    # Dateiname (klein) -> Pfad. Bei Namensgleichheit gewinnt der kuerzere Pfad (die "Hauptdatei").
    nach_name = {}
    for f in dateien:
        n = os.path.basename(f['path'])[:-3].lower()
        if n not in nach_name or len(f['path']) < len(nach_name[n]):
            nach_name[n] = f['path']
    kanten, offen = [], 0
    for ziel_name, quellen in idx.items():
        ziel = nach_name.get(ziel_name)
        if not ziel:
            offen += 1                       # Verweis auf etwas, das es (noch) nicht gibt
            continue
        for q in quellen:
            if q != ziel:
                kanten.append([q, ziel])
    return {'kanten': kanten, 'uebersprungen': skip, 'unaufgeloest': offen}

SUCH_CACHE = {'ts': 0, 'idx': None}

def _such_index():
    """Datei -> (Kleinbuchstaben-Text, Frontmatter-Felder). 120 s gecacht wie der Backlink-Index.

    Grenze: Dateien mit `ki_freigabe: gesperrt` werden NICHT
    volltextig gelesen. Sie sind trotzdem auffindbar -- aber nur ueber ihren Dateinamen, und der
    Treffer kommt ohne Textausschnitt zurueck."""
    if SUCH_CACHE['idx'] is not None and time.time() - SUCH_CACHE['ts'] < 120:
        return SUCH_CACHE['idx']
    idx = []
    for root, dirs, files in os.walk(VAULT):
        dirs[:] = [x for x in dirs if not x.startswith('.')
                   and x not in ('node_modules', '_backups', 'Backups', '__pycache__')]
        for fn in files:
            if not fn.endswith('.md'):
                continue
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, VAULT).replace('\\', '/')
            name = fn[:-3]
            if rel.startswith('02_kunden/') and GESPERRT.search(head_of(full, 2000)):  # Kundenblaetter; Projektordner lesbar
                idx.append({'path': rel, 'name': name, 'text': None, 'fm': {}, 'gesperrt': True})
                continue
            try:
                with open(full, encoding='utf-8', errors='replace') as fh:
                    text = fh.read(200000)
            except OSError:
                continue
            if GESPERRT.search(text[:2000]):
                idx.append({'path': rel, 'name': name, 'text': None, 'fm': {}, 'gesperrt': True})
                continue
            fm = {}
            m = re.match(r'---\n(.*?)\n---', text, re.S)
            if m:
                for zeile in m.group(1).split('\n'):
                    kv = re.match(r'^([a-zA-Z_][\w-]*):\s*(.*)$', zeile)
                    if kv:
                        fm[kv.group(1).lower()] = kv.group(2).strip().strip('"\'[]')
            idx.append({'path': rel, 'name': name, 'text': text, 'tief': text.lower(),
                        'fm': fm, 'gesperrt': False})
    SUCH_CACHE.update(ts=time.time(), idx=idx)
    return idx

def api_suche(q, typ='', status='', limit=60):
    """Volltextsuche. Mehrere Woerter = alle muessen vorkommen (UND). Treffer im Dateinamen
    zaehlen mehr als im Text, damit die gesuchte Datei oben steht."""
    q = (q or '').strip()
    if len(q) < 2:
        return {'treffer': [], 'hinweis': 'Suchbegriff zu kurz'}
    worte = [w for w in q.lower().split() if w]
    raus, gesperrt_gefunden = [], 0
    for e in _such_index():
        name_tief = e['name'].lower()
        pfad_tief = e['path'].lower()
        if typ and e['fm'].get('typ', '') != typ:
            continue
        if status and e['fm'].get('status', '') != status:
            continue
        if e['gesperrt']:
            # nur Name/Pfad, nie Inhalt
            if all(w in name_tief or w in pfad_tief for w in worte):
                gesperrt_gefunden += 1
                raus.append({'path': e['path'], 'name': e['name'], 'punkte': 40,
                             'ausschnitt': '', 'gesperrt': True, 'typ': '', 'status': ''})
            continue
        if not all(w in e['tief'] or w in pfad_tief for w in worte):
            continue
        punkte = 0
        if all(w in name_tief for w in worte):
            punkte += 100
        if q.lower() in name_tief:
            punkte += 60
        punkte += min(40, sum(e['tief'].count(w) for w in worte))
        # Ausschnitt um den ersten Treffer im Text
        pos = min([p for p in (e['tief'].find(w) for w in worte) if p >= 0] or [-1])
        if pos < 0:
            ausschnitt = ''
        else:
            von = max(0, pos - 60)
            ausschnitt = re.sub(r'\s+', ' ', e['text'][von:pos + 140]).strip()
            if von:
                ausschnitt = '… ' + ausschnitt
        raus.append({'path': e['path'], 'name': e['name'], 'punkte': punkte,
                     'ausschnitt': ausschnitt, 'gesperrt': False,
                     'typ': e['fm'].get('typ', ''), 'status': e['fm'].get('status', '')})
    raus.sort(key=lambda x: (-x['punkte'], x['path']))
    return {'treffer': raus[:max(1, min(200, limit))], 'gesamt': len(raus),
            'gesperrt_nur_name': gesperrt_gefunden}

def api_file(rel, full_view=False):
    full = vault_md(rel)
    if not full or not os.path.isfile(full):
        return {'error': 'ungueltiger Pfad'}
    # VOR dem Lesen: aendert sich die Datei waehrenddessen, meldet Speichern Konflikt. Als String, weil
    # JavaScript eine JSON-Zahl dieser Groesse (> 2^53) rundet.
    mtime_ns = str(os.stat(full).st_mtime_ns)
    with open(full, encoding='utf-8', errors='replace') as fh:
        head = fh.read(2000)
        locked = bool(GESPERRT.search(head))
        if locked and not full_view:
            return {'gesperrt': True}  # Standard: Inhalt bleibt draussen (LLM-Kontext-Schutz)
        # Kein stilles Kuerzen: was laenger ist, kommt mit gekuerzt=True und ist in der UI nur lesbar
        text = head + fh.read(DATEI_MAX - len(head))
        return {'text': text, 'gesperrt': locked, 'mtime_ns': mtime_ns, 'gekuerzt': bool(fh.read(1))}

# ---------- Usage (Tokens aus ~/.claude/projects, lokal gezaehlt; Fenster 7d/30d/all) ----------
USG = {}

def usage_tokens(window='7d'):
    key = window if window in ('7d', '30d', 'all') else '7d'
    cache = USG.get(key)
    if cache and time.time() - cache['ts'] < 300:
        return cache['val']
    days = {'7d': 7, '30d': 30}.get(key)
    cut, ohne_id = (time.time() - days * 86400) if days else 0, 0
    root = os.path.join(os.path.expanduser('~'), '.claude', 'projects')
    # Eine Antwort steht je Inhaltsblock als eigene Zeile mit derselben Nachrichten-Id im Protokoll
    # (und fortgesetzte Sitzungen kopieren sie in eine neue Datei) -> je Id nur einmal zaehlen. Die
    # fruehen Zeilen (thinking/erster Block) tragen aber nur einen Streaming-Zwischenstand von
    # output_tokens, erst die letzte Zeile der Id den Endwert -- darum je Feld das Maximum ueber
    # alle Zeilen derselben Id nehmen, nicht blind die zuerst gelesene Zeile.
    # Subagenten schreiben nach <sitzung>/subagents/*.jsonl, eine Ebene tiefer -- Workflow-Agenten
    # nochmal eine Ebene tiefer nach .../subagents/workflows/<wf>/agent-*.jsonl (zweites ** faengt
    # beide Tiefen, da ** auch leer passt).
    gesehen = {}
    if os.path.isdir(root):
        for p in (globmod.glob(os.path.join(root, '*', '*.jsonl'))
                  + globmod.glob(os.path.join(root, '*', '**', 'subagents', '**', '*.jsonl'), recursive=True)):
            try:
                if cut and os.path.getmtime(p) < cut:
                    continue
                for line in open(p, encoding='utf-8', errors='replace'):
                    if '"output_tokens"' not in line:
                        continue
                    if '"toolUseResult":' in line:
                        # Agent-Aufruf im Haupt-Thread: traegt die Usage der LETZTEN Subagenten-
                        # Nachricht ohne eigene Id -- die zaehlt schon ueber subagents/*.jsonl,
                        # sonst doppelt.
                        continue
                    if cut:
                        ts = re.search(r'"timestamp":"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)', line)
                        if ts and calendar.timegm(time.strptime(ts.group(1), '%Y-%m-%dT%H:%M:%S')) < cut:
                            continue
                    werte = {}
                    for feld, k in (('in', '"input_tokens":(\\d+)'), ('out', '"output_tokens":(\\d+)'),
                                    ('cc', '"cache_creation_input_tokens":(\\d+)')):
                        m = re.search(k, line)
                        if m:
                            werte[feld] = int(m.group(1))
                    mid = re.search(r'"id":"(msg_[^"]+)"', line) or re.search(r'"requestId":"([^"]+)"', line)
                    if mid:
                        eintrag = gesehen.setdefault(mid.group(1), {})
                        for feld, wert in werte.items():
                            if wert > eintrag.get(feld, -1):
                                eintrag[feld] = wert
                    else:
                        ohne_id += sum(werte.values())
            except Exception:
                pass
    tot = ohne_id + sum(sum(eintrag.values()) for eintrag in gesehen.values())
    USG[key] = {'ts': time.time(), 'val': tot}
    return tot

def api_usage(window):
    return {'window': window if window in ('7d', '30d', 'all') else '7d', 'tokens': usage_tokens(window)}

# ---------- Termine (ICS aus dashboard.json + lokale termine.txt) ----------
TERM = {'ts': 0, 'evs': None, 'err': ''}
LOKAL_TERMINE = os.path.join(BASE, 'termine.txt')  # Zeile: YYYY-MM-DD [HH:MM] Titel

def _ics_parse(raw, quelle_name, farbe):
    raw = raw.replace('\r\n ', '').replace('\n ', '')  # ICS-Zeilenfaltung aufheben
    out = []
    for m in re.finditer(r'BEGIN:VEVENT(.*?)END:VEVENT', raw, re.S):
        b = m.group(1)  # Vereinfachung: DTSTART pur, keine RRULE-Expansion — Serientermine zeigen nur den Start
        dt = re.search(r'DTSTART[^:]*:(\d{8})(?:T(\d{4})\d*(Z)?)?', b)
        su = re.search(r'SUMMARY[^:]*:(.*)', b)
        lo = re.search(r'LOCATION[^:]*:(.*)', b)
        if dt:
            d, t = dt.group(1), dt.group(2) or ''
            if dt.group(3):   # ...Z = UTC -> Ortszeit dieses Rechners
                try:
                    lt = time.localtime(calendar.timegm(time.strptime(d + t, '%Y%m%d%H%M')))
                    d, t = time.strftime('%Y%m%d', lt), time.strftime('%H%M', lt)
                except (ValueError, OSError, OverflowError):
                    pass  # Termin vor 1970 (wirft unter Windows) oder ungueltiges Datum:
                    # Rohwert behalten statt mit diesem einen Termin den ganzen Kalender zu kippen
            # Bewusst schlicht: TZID=... bleibt als Ortszeit stehen -- ohne tzdata (fehlt unter Windows) kennt
            # zoneinfo keine Zonen; Termine aus einer FREMDEN Zeitzone erscheinen deshalb verschoben.
            out.append({'am': '%s-%s-%s' % (d[:4], d[4:6], d[6:8]) + ((' %s:%s' % (t[:2], t[2:])) if t else ''),
                        'was': (su.group(1).strip() if su else '?'), 'quelle': 'extern',
                        'ort': (lo.group(1).strip() if lo else ''), 'kalender': quelle_name, 'farbe': farbe,
                        'ganztags': not t})
    return out

def ics_events():
    """Alle eingeschalteten Kalender zusammen. Ein Fehler kippt nicht die anderen."""
    if time.time() - TERM['ts'] < 600 and TERM['evs'] is not None:
        return TERM['evs'], TERM['err']
    try:
        quellen = [k for k in kal_liste() if k.get('url') and k.get('an', True)]
    except RuntimeError as e:   # lokale Termine sollen trotzdem erscheinen
        return [], str(e)
    evs, fehler = [], []
    for k in quellen:
        try:
            evs += _ics_parse(_fetch_ics(k['url'], k.get('username') or '', kal_password(k)),
                              k.get('name') or 'Kalender', k.get('farbe') or KAL_FARBEN[0])
        except Exception as e:
            fehler.append('%s: %s' % (k.get('name') or k['id'], e))
    if not quellen:  # Altweg: oeffentlicher Link/Datei aus dashboard.json
        src = (api_config().get('kalender_ics') or '').strip().replace('webcal://', 'https://')
        if src:
            try:
                raw = (_fetch_ics(src, '', '') if src.startswith('http')
                       else open(src if os.path.isabs(src) else os.path.join(VAULT, src), encoding='utf-8', errors='replace').read())
                evs += _ics_parse(raw, 'Kalender', KAL_FARBEN[0])
            except Exception as e:
                fehler.append('%s' % e)
        else:
            evs = None
    err = ' · '.join(fehler)
    TERM.update(ts=time.time(), evs=evs, err=err)
    return evs, err

# Lokale Termine liegen als JSON vor (Ort, Kategorie, Ende, Wiederholung ... passen in keine Textzeile).
# termine.txt bleibt als Altbestand liegen und wird beim ersten Laden einmalig uebernommen.
TERMINE_JSON = os.path.join(BASE, 'termine.json')
KATEGORIEN = {'termin': '#21F1A8', 'kunde': '#66B8FF', 'privat': '#B18CFF', 'wichtig': '#FF6B6B',
              'intern': '#FFC24D', 'urlaub': '#4DD9E8'}
WDH = ('', 'taeglich', 'werktags', 'woechentlich', 'zweiwoechentlich', 'monatlich', 'jaehrlich', 'frei')
DT_RE = re.compile(r'\A\d{4}-\d\d-\d\d(?:[T ]\d\d:\d\d)?\Z')

def _dt_gueltig(s):
    """DT_RE prueft nur das MUSTER (YYYY-MM-DD[THH:MM]), nicht den Wert -- '2026-02-30' oder
    '...T24:00' passen durch und lassen _vorkommen_ende/termin_vorkommen spaeter mit ValueError
    aufs ganze Fenster kippen. Hier den echten Kalenderwert pruefen, bevor der Termin gespeichert wird."""
    from datetime import date, datetime
    try:
        (datetime if len(s) > 10 else date).fromisoformat(s)
        return True
    except ValueError:
        return False
# Bewusst einfach: globales Lock um Lesen-Aendern-Schreiben von termine.json -- zwei gleichzeitige
# Speichervorgaenge verloeren sonst einen der beiden Termine.
TERMINE_LOCK = threading.Lock()

def termine_laden():
    if os.path.isfile(TERMINE_JSON):
        # Kaputte Datei NICHT als leere Liste ausgeben: der naechste Schreibvorgang wuerde sonst
        # alle Termine mit dieser leeren Liste ueberschreiben.
        try:
            d = json.load(open(TERMINE_JSON, encoding='utf-8'))
        except Exception as e:
            raise RuntimeError('termine.json unlesbar (%s) -- bitte Datei pruefen' % e)
        if not isinstance(d, list):
            raise RuntimeError('termine.json ist keine Liste -- bitte Datei pruefen')
        return d
    # Einmal-Migration aus termine.txt
    alt = []
    if os.path.isfile(LOKAL_TERMINE):
        for line in open(LOKAL_TERMINE, encoding='utf-8', errors='replace'):
            m = re.match(r'(\d{4}-\d\d-\d\d)(?:\s+(\d\d:\d\d))?\s+(.+)', line.strip())
            if m:
                alt.append({'id': uuid.uuid4().hex[:12], 'titel': m.group(3),
                            'beginn': m.group(1) + ('T' + m.group(2) if m.group(2) else ''),
                            'ende': '', 'ganztags': not m.group(2), 'ort': '', 'kategorie': 'termin',
                            'wiederholung': '', 'wdh_intervall': 1, 'wdh_einheit': 'tage',
                            'erinnerung': 0, 'beschreibung': '', 'teilnehmer': ''})
    if alt:
        termine_speichern(alt)
    return alt

def termine_speichern(liste):
    return write_file(TERMINE_JSON, json.dumps(liste, indent=1, ensure_ascii=False))

def termin_pruefe(d, alt=None):
    """Baut aus dem Formular einen sauberen Termin-Datensatz; (None, Fehler) bei Unsinn."""
    t = dict(alt or {})
    titel = (d.get('titel') or '').strip()
    beginn = (d.get('beginn') or '').strip().replace(' ', 'T')
    if not titel:
        return None, {'error': 'Titel fehlt'}
    if not DT_RE.match(beginn) or not _dt_gueltig(beginn):
        return None, {'error': 'Beginn muss YYYY-MM-DD oder YYYY-MM-DDTHH:MM sein'}
    ende = (d.get('ende') or '').strip().replace(' ', 'T')
    if ende and (not DT_RE.match(ende) or not _dt_gueltig(ende)):
        return None, {'error': 'Ende muss YYYY-MM-DD oder YYYY-MM-DDTHH:MM sein'}
    # Ein Ende OHNE Uhrzeit ist inklusiv, auch wenn der Beginn eine Uhrzeit hat --
    # als Zeichenkette verglichen waere '2026-08-11' < '2026-08-11T09:00' (kuerzerer String gilt als
    # kleiner) und das Formular koennte am selben Tag keinen Termin mehr abschliessen.
    if ende and ende < (beginn[:10] if len(ende) == 10 else beginn):
        return None, {'error': 'Ende liegt vor dem Beginn'}
    wdh_bis = (d.get('wdh_bis') or '').strip()
    # Wie bei beginn/ende: DT_RE-artiges Muster allein reicht nicht ('2026-02-30' passt durch) --
    # ein ungueltiger Wert liess termin_vorkommen() spaeter mit ValueError den ganzen Kalender kippen.
    if wdh_bis and (not re.match(r'\A\d{4}-\d\d-\d\d\Z', wdh_bis) or not _dt_gueltig(wdh_bis)):
        return None, {'error': 'Wiederholen bis muss YYYY-MM-DD sein'}
    wdh = d.get('wiederholung') if d.get('wiederholung') in WDH else ''
    t.update({
        'id': t.get('id') or uuid.uuid4().hex[:12],
        'titel': re.sub(r'[\r\n]+', ' ', titel)[:200],
        'beginn': beginn, 'ende': ende,
        'ganztags': bool(d.get('ganztags')) or len(beginn) == 10,
        'ort': re.sub(r'[\r\n]+', ' ', (d.get('ort') or '').strip())[:200],
        'kategorie': d.get('kategorie') if d.get('kategorie') in KATEGORIEN else 'termin',
        'wiederholung': wdh,
        'wdh_intervall': _clamp_int(d.get('wdh_intervall'), 1, 365, 1),
        'wdh_einheit': d.get('wdh_einheit') if d.get('wdh_einheit') in ('tage', 'wochen', 'monate') else 'tage',
        'wdh_bis': wdh_bis,
        'erinnerung': _clamp_int(d.get('erinnerung'), 0, 10080, 0),
        'beschreibung': (d.get('beschreibung') or '').strip()[:4000],
        'teilnehmer': re.sub(r'[\r\n]+', ', ', (d.get('teilnehmer') or '').strip())[:1000],
    })
    return t, None

def _plus_monate(d, n):
    j, m = d.year + (d.month - 1 + n) // 12, (d.month - 1 + n) % 12 + 1
    return d.replace(year=j, month=m, day=min(d.day, calendar.monthrange(j, m)[1]))

def _letzter_kalendertag(ende):
    """Kalendertag, an dem ein Termin-Ende zuletzt noch dazugehoert: ohne Uhrzeit
    gilt der Tag inklusiv, mit Uhrzeit 00:00 nicht mehr (dann zaehlt der Vortag als letzter Tag) --
    jede andere Uhrzeit liegt noch IM Tag und der zaehlt normal."""
    if len(ende) > 10 and ende[11:16] == '00:00':
        from datetime import date, timedelta
        return (date.fromisoformat(ende[:10]) - timedelta(days=1)).isoformat()
    return ende[:10]

def termin_vorkommen(t, von, bis):
    """Expandiert die Wiederholung im Fenster [von,bis]; ohne Wiederholung genau ein Vorkommen."""
    from datetime import date, timedelta
    tag0 = t['beginn'][:10]
    zeit = t['beginn'][11:16] if len(t['beginn']) > 10 else ''
    # ganztags: Uhrzeit am Ende zaehlt nicht (wie _vorkommen_ende) -- sonst zeigte der Mini-Monat den Endtag, die Woche nicht
    ende_tag = (t['ende'][:10] if t.get('ganztags') else _letzter_kalendertag(t['ende'])) if t.get('ende') else tag0
    dauer_tage = (date.fromisoformat(ende_tag) - date.fromisoformat(tag0)).days if ende_tag > tag0 else 0
    wdh = t.get('wiederholung') or ''
    if not wdh:
        return [tag0] if von <= tag0 <= bis or (dauer_tage and tag0 <= bis and ende_tag >= von) else []
    start, grenze = date.fromisoformat(tag0), date.fromisoformat(min(bis, t.get('wdh_bis') or bis))
    von_d = date.fromisoformat(von)
    # Erst NACH Abzug der Dauer abbrechen: ein mehrtaegiges Vorkommen, das vor `grenze` beginnt,
    # kann noch bis in den Fensteranfang hineinreichen (gleiche Ueberlappungsregel wie oben/unten).
    if von_d > grenze + timedelta(days=dauer_tage):
        return []
    schritt = {'taeglich': timedelta(days=1), 'werktags': timedelta(days=1),
               'woechentlich': timedelta(days=7), 'zweiwoechentlich': timedelta(days=14)}.get(wdh)
    if wdh == 'frei':
        einheit = t.get('wdh_einheit', 'tage')
        n = t.get('wdh_intervall', 1)
        schritt = timedelta(days=n) if einheit == 'tage' else timedelta(weeks=n) if einheit == 'wochen' else None
    monate = (1 if wdh == 'monatlich' else 12 if wdh == 'jaehrlich'
              else t.get('wdh_intervall', 1) if wdh == 'frei' and t.get('wdh_einheit') == 'monate' else 0)
    # Einstieg kurz vor `von` statt am Serienstart -- sonst frisst eine alte Tagesserie die
    # 1200er-Grenze, bevor sie das Fenster erreicht. Jedes Vorkommen wird aus dem ORIGINAL-Beginn
    # berechnet (31.01. -> 28.02. -> 31.03.), nicht aus dem schon gekappten Vormonat. Bei einem
    # mehrtaegigen Vorkommen (dauer_tage) zusaetzlich einen Schritt weiter zurueck: sonst fehlt genau
    # das Vorkommen, das VOR `von` beginnt und noch hineinreicht (gleiche Ueberlappungsregel wie beim
    # Einzeltermin unten bei `dauer_tage and ...`).
    # Genau ein Schritt zurueck -- ist ein Vorkommen laenger als der Serienabstand (z. B. taeglich
    # mit 3 Tagen Dauer), fehlen am Fensteranfang fruehere, noch laufende Vorkommen; dann ceil(dauer/schritt) zurueck.
    k0 =(max(0, (von_d - start).days // schritt.days - (1 if dauer_tage else 0)) if schritt else
          max(0, ((von_d.year - start.year) * 12 + von_d.month - start.month) // monate - 1) if monate else 0)
    raus = []
    for k in range(k0, k0 + 1200):
        cur = start + k * schritt if schritt else _plus_monate(start, k * monate) if monate else start
        if cur > grenze:
            break
        letzter_tag = cur + timedelta(days=dauer_tage) if dauer_tage else cur
        if letzter_tag >= von_d and not (wdh == 'werktags' and cur.weekday() > 4):
            raus.append(cur.isoformat())
        if not (schritt or monate):
            break
    return raus

def _vorkommen_ende(t, tag):
    """Eigenes Ende EINES Vorkommens: Vorkommen-Tag + urspruengliche Dauer
    (ende - beginn des Termins; bei ganztags ganze Tage) -- NICHT das Ende der Serie selbst,
    das bei spaeteren Vorkommen vor dem Vorkommen-Tag laege und die Kalenderansicht es verwerfen
    liesse. serie_beginn/serie_ende (s.u.) tragen weiter die Originalwerte fuers Bearbeiten.
    Ein Ende OHNE Uhrzeit gilt inklusive, auch bei einem Termin MIT Uhrzeit (so schickt es
    das Formular bei leerer Endzeit) -- dann wie beim ganztags-Termin in ganzen Tagen rechnen und ein
    reines Datum liefern, nie ein T00:00 (das waere exklusiv und liesse den letzten Tag verschwinden).
    Ungueltige Werte im Altbestand (z.B. von Hand editierte termine.json mit '24:00') duerfen local_events
    nicht kippen -- termin_pruefe weist sowas bei neuen/bearbeiteten Terminen ab (_dt_gueltig), hier
    faellt ein trotzdem vorhandener kaputter Wert auf das gespeicherte Ende zurueck."""
    ende = t.get('ende', '')
    if not ende:
        return ''
    from datetime import date, datetime
    beginn = t['beginn']
    try:
        if t.get('ganztags') or len(ende) <= 10:
            dauer = date.fromisoformat(ende[:10]) - date.fromisoformat(beginn[:10])
            return (date.fromisoformat(tag) + dauer).isoformat()
        dauer = datetime.fromisoformat(ende) - datetime.fromisoformat(beginn)
        zeit = beginn[11:16]
        return (datetime.fromisoformat(tag + 'T' + zeit) + dauer).isoformat(timespec='minutes')
    except ValueError:
        # z.B. Altbestand mit ganztags:false, Beginn ohne Uhrzeit (zeit='') und Ende mit Uhrzeit --
        # tag+'T'+zeit waere dann kein gueltiges Isoformat. Gespeichertes Ende roh zurueckgeben.
        return ende

def local_events(von='0000-00-00', bis='9999-99-99'):
    """Ein Eintrag je Vorkommen; `id` bleibt die Termin-Id (Serien teilen sich eine). Ein einzelner
    kaputter Altbestands-Termin (z.B. von Hand editiertes Datum wie '2026-02-30' im Ende oder in
    wdh_bis) wird uebersprungen, statt mit ValueError den ganzen Kalender zu kippen."""
    out = []
    for t in termine_laden():
        if not t.get('beginn'):
            continue
        zeit = t['beginn'][11:16] if len(t['beginn']) > 10 and not t.get('ganztags') else ''
        try:
            vorkommen = termin_vorkommen(t, von, bis)
        except (ValueError, OverflowError):   # OverflowError: Grenze nahe 9999-12-31 plus Dauer
            continue
        for tag in vorkommen:
            out.append({'am': tag + ((' ' + zeit) if zeit else ''), 'was': t.get('titel', ''),
                        'quelle': 'lokal', 'id': t['id'], 'ort': t.get('ort', ''),
                        'kategorie': t.get('kategorie', 'termin'), 'farbe': KATEGORIEN.get(t.get('kategorie'), KATEGORIEN['termin']),
                        'ende': _vorkommen_ende(t, tag), 'ganztags': bool(t.get('ganztags')),
                        'beschreibung': t.get('beschreibung', ''), 'teilnehmer': t.get('teilnehmer', ''),
                        'erinnerung': t.get('erinnerung', 0), 'wiederholung': t.get('wiederholung', ''),
                        'wdh_intervall': t.get('wdh_intervall', 1), 'wdh_einheit': t.get('wdh_einheit', 'tage'),
                        'wdh_bis': t.get('wdh_bis', ''), 'serie': bool(t.get('wiederholung')),
                        # Originalwerte der Serie: beim Bearbeiten gehoeren DIESE in die Karte, nicht das Vorkommen
                        'serie_beginn': t['beginn'], 'serie_ende': t.get('ende', '')})
    return out

def _im_fenster(e, von, bis):
    """Ueberlappung statt Beginn-im-Fenster: ein Urlaub vom 1. bis 20. gehoert auch ins Fenster 10.-15.
    Ein Ende MIT Uhrzeit 00:00 gehoert nicht mehr zu diesem Tag -- dann zaehlt der Vortag."""
    ende = e.get('ende') or ''
    ende_tag = _letzter_kalendertag(ende) if ende else e['am'][:10]
    return e['am'][:10] <= bis and max(e['am'][:10], ende_tag) >= von

def _lokal_mit_fehler(von, bis, err):
    """Kaputte termine.json: externe Termine trotzdem zeigen, der Fehler kommt als Hinweis mit."""
    try:
        return local_events(von, bis), err
    except RuntimeError as e:
        return [], ' · '.join(x for x in (err, '%s' % e) if x)

def api_termine():
    evs, err = ics_events()
    today = time.strftime('%Y-%m-%d')
    limit = time.strftime('%Y-%m-%d', time.localtime(time.time() + 7 * 86400))
    lokal, err = _lokal_mit_fehler(today, limit, err)
    alle = sorted([e for e in (evs or []) + lokal if _im_fenster(e, today, limit)], key=lambda e: e['am'])
    return {'events': None if evs is None and not lokal else alle, 'error': err or None}

def api_kalender(von, bis):
    evs, err = ics_events()
    lokal, err = _lokal_mit_fehler(von, bis, err)
    alle = sorted([e for e in (evs or []) + lokal if _im_fenster(e, von, bis)], key=lambda e: e['am'])
    return {'events': alle, 'error': err or None, 'kategorien': KATEGORIEN}

def api_termin_new(d):
    t, err = termin_pruefe(d)
    if err:
        return err
    with TERMINE_LOCK:
        liste = termine_laden()
        liste.append(t)
        r = termine_speichern(liste)
    return r if 'error' in r else {'ok': True, 'id': t['id']}

def api_termin_save(d):
    with TERMINE_LOCK:
        liste = termine_laden()
        idx = next((i for i, x in enumerate(liste) if x.get('id') == d.get('id')), -1)
        if idx < 0:
            return {'error': 'Termin nicht gefunden'}
        t, err = termin_pruefe(d, liste[idx])
        if err:
            return err
        liste[idx] = t
        return termine_speichern(liste)

def api_termin_delete(d):
    with TERMINE_LOCK:
        liste = termine_laden()
        neu = [x for x in liste if x.get('id') != d.get('id')]
        if len(neu) == len(liste):
            return {'error': 'Termin nicht gefunden'}
        return termine_speichern(neu)

def api_termin_suche(q):
    q = (q or '').strip().lower()
    if len(q) < 2:
        return {'treffer': []}
    tr = [t for t in termine_laden()
          if q in (t.get('titel', '') + ' ' + t.get('ort', '') + ' ' + t.get('beschreibung', '')).lower()]
    return {'treffer': sorted([{'id': t['id'], 'titel': t.get('titel', ''), 'beginn': t.get('beginn', ''),
                                'ort': t.get('ort', ''), 'kategorie': t.get('kategorie', 'termin')}
                               for t in tr], key=lambda x: x['beginn'])[:50]}

# ---------- Uptime (Auto-Sites aus Projekten + uptime.txt, alle 60 s) ----------
UP = {'ts': 0, 'sites': [], 'hist': {}}

def ping(url):
    code = '?'
    for method in ('HEAD', 'GET'):  # HEAD zuerst, GET-Fallback fuer Server ohne HEAD
        try:
            req = urllib.request.Request(url, method=method, headers={'User-Agent': 'Mozilla/5.0 puox-monitor'})
            return urllib.request.urlopen(req, timeout=6).status
        except urllib.error.HTTPError as e:
            code = e.code
        except Exception as e:
            code = e.__class__.__name__
    return code

def all_sites():
    sites = {}
    for p in globmod.glob(os.path.join(VAULT, '02_kunden', '*', '*', '*-website.md')):
        dom = os.path.basename(p)[:-len('-website.md')]
        if '.' in dom:  # nur echte Domains; Kunden-Projekte in Produktion automatisch
            h = head_of(p, 800)
            if re.search(r'^kunde:\s*"?\[\[.+\]\]', h, re.M) and re.search(r'^status:\s*produktion', h, re.M):
                sites[dom] = 'https://' + dom
    cfg = os.path.join(BASE, 'uptime.txt')
    if os.path.isfile(cfg):
        for line in open(cfg, encoding='utf-8'):
            parts = line.split()
            if len(parts) >= 2 and not line.lstrip().startswith('#'):
                sites[parts[0]] = parts[1]
    return sites

def uptime_loop():
    while True:
        try:   # ein Fehler (z. B. kaputte uptime.txt) darf den Thread nicht fuer immer beenden
            res = []
            for name, url in sorted(all_sites().items()):
                code = ping(url)
                ok = code == 200
                res.append({'name': name, 'url': url, 'status': code, 'ok': ok})
                UP['hist'].setdefault(name, []).append(1 if ok else 0)
                UP['hist'][name] = UP['hist'][name][-1440:]
            UP['ts'], UP['sites'] = time.time(), res
        except Exception:
            pass
        time.sleep(60)

def api_uptime():
    h = UP['hist']
    pct = round(100 * sum(sum(v) for v in h.values()) / max(1, sum(len(v) for v in h.values())), 1) if h else None
    return {'ts': UP['ts'], 'sites': UP['sites'], 'pct': pct,
            'hist': {k: v[-40:] for k, v in h.items()},
            'sitepct': {k: round(100 * sum(v) / max(1, len(v)), 1) for k, v in h.items()}}

# ---------- Auto-Backup (>24 h -> puox.exe backup; Anzeige >=25 h rot im UI) ----------
BAK = {'state': 'aus', 'info': ''}

def backup_loop():
    time.sleep(30)
    while True:
        try:
            bdir = os.path.join(VAULT, '_backups')
            zips = [os.path.join(bdir, f) for f in os.listdir(bdir) if f.endswith('.zip')] if os.path.isdir(bdir) else []
            age = min((time.time() - os.path.getmtime(z) for z in zips), default=1e9) / 3600
            if age > 24:
                BAK.update(state='laeuft', info='gestartet ' + time.strftime('%H:%M'))
                out, err, rc = run([PUOX, 'backup'], timeout=3600)
                BAK.update(state='ok' if rc == 0 else 'fehler',
                           info=('fertig ' if rc == 0 else 'FEHLER ') + time.strftime('%H:%M'))
            elif BAK['state'] == 'aus':
                BAK.update(state='ok', info='Backup frisch')
        except Exception as e:
            BAK.update(state='fehler', info=str(e))
        time.sleep(600)

# ---------- Aufgaben / Kunden (Schreibpfade) ----------
POT = os.path.join(VAULT, '02_kunden', 'potenzielle-kunden.md')

def api_task_new(d):
    titel = re.sub(r'[<>:"/\\|?*]', '', (d.get('titel') or '')).strip()
    if not titel:
        return {'error': 'Titel fehlt'}
    kunde = (d.get('kunde') or '').strip()
    # kunde wird Teil des Pfads -- nur ein vorhandener Kundenordner, exakt so geschrieben (listdir
    # liefert nie `.`, `..` oder Trenner); Umlaute, `&`, `()` sind nach Konvention erlaubt
    kdir = os.path.join(VAULT, '02_kunden')
    if kunde and not (kunde in (os.listdir(kdir) if os.path.isdir(kdir) else []) and os.path.isdir(os.path.join(kdir, kunde))):
        return {'error': 'unbekannter Kunde'}
    # Ablage: intern/ bzw. kunden/<kunde>/offen/; Dateiname klein mit Bindestrichen
    datei = re.sub(r'-+', '-', titel.lower().replace(' ', '-')).strip('-') + '.md'
    path = os.path.join(VAULT, '09_aufgaben', *(('kunden', kunde, 'offen') if kunde else ('intern',)), datei)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        return {'error': 'Aufgabe existiert schon'}
    fm = ['typ: aufgabe', 'status: offen', 'prioritaet: ' + (d.get('prioritaet') or 'mittel')]
    if d.get('bereich'):
        fm.append('bereich: ' + d['bereich'])
    if d.get('faellig'):
        fm.append('faellig: ' + d['faellig'])
    if kunde:
        fm.append('kunde: "[[%s]]"' % kunde)
        # Eine neue Aufgabe
        # zu einem gesperrten Kunden bekommt ki_freigabe nicht automatisch.
        # Wer eine einzelne Aufgabe sperren will, traegt das Feld von Hand ein.
    r = write_file(path, '---\n' + '\n'.join(fm) + '\n---\n\n# ' + titel + '\n\n' + (d.get('notiz') or '') + '\n')
    r.setdefault('path', os.path.relpath(path, VAULT).replace('\\', '/'))
    return r

def api_task_save(d):
    full = vault_md((d.get('path') or '').replace('\\', '/'))
    if not full or not os.path.isfile(full):
        return {'error': 'ungueltiger Pfad'}
    # Zone am AUFGELOESTEN Pfad pruefen -- `09_aufgaben/../CLAUDE.md` faengt textlich mit der Zone an
    rel = os.path.relpath(full, os.path.realpath(VAULT)).replace('\\', '/')
    ok_scope = rel.startswith('09_aufgaben/') or rel.startswith('02_kunden/') or 'typ: aufgabe' in head_of(full)
    if not ok_scope:
        return {'error': 'Pfad ausserhalb der erlaubten Schreibzonen'}
    # Konfliktschutz: wurde die Datei seit dem Oeffnen geaendert, nicht ueberschreiben. mtime_ns reist
    # als String -- als JSON-Zahl (~1.8e18 > 2^53) rundete JavaScript die letzten Stellen.
    if d.get('mtime_ns') is not None:
        try:
            stand = int(d['mtime_ns'])
        except (TypeError, ValueError):
            return {'error': 'Ungültiger Dateistand (mtime_ns) — bitte neu laden'}
        if stand != os.stat(full).st_mtime_ns:
            return {'error': 'Datei wurde seit dem Öffnen geändert — bitte neu laden'}
    r = write_file(full, d.get('text') or '')
    if r.get('ok'):
        r['mtime_ns'] = str(os.stat(full).st_mtime_ns)
    return r

def api_pot():
    out = []
    if os.path.isfile(POT):
        for l in open(POT, encoding='utf-8', errors='replace'):
            if l.startswith('- '):
                t = l[2:].strip().split(' — ')
                name, preis, notiz = t[0], 0, ''
                rest = t[1:]
                if rest:
                    m = re.match(r'^(\d+(?:[.,]\d+)?)\s*€?$', rest[0].strip())
                    if m:
                        preis, notiz = float(m.group(1).replace(',', '.')), ' — '.join(rest[1:])
                    else:
                        notiz = ' — '.join(rest)
                out.append({'name': name, 'preis': preis, 'notiz': notiz})
    return {'eintraege': out}

def api_pot_new(d):
    name = (d.get('name') or '').strip()
    if not name:
        return {'error': 'Name fehlt'}
    preis = (d.get('preis') or '').strip().replace(',', '.')
    notiz = (d.get('notiz') or '').strip()
    teile = [name]
    if preis:
        try:
            teile.append('%g€' % float(preis))
        except ValueError:
            pass
    if notiz:
        teile.append(notiz)
    cur = open(POT, encoding='utf-8', errors='replace').read() if os.path.isfile(POT) else ''
    return write_file(POT, cur + ('' if not cur or cur.endswith('\n') else '\n') + '- ' + ' — '.join(teile) + '\n')

def api_pot_remove(d):
    name = (d.get('name') or '').strip()
    if not name or not os.path.isfile(POT):
        return {'error': 'Name fehlt'}
    lines = open(POT, encoding='utf-8', errors='replace').read().splitlines()
    neu = [l for l in lines if not (l.startswith('- ') and l[2:].strip().split(' — ', 1)[0] == name)]
    if len(neu) == len(lines):
        return {'error': 'nicht gefunden'}
    return write_file(POT, '\n'.join(neu) + ('\n' if neu else ''))

def api_kunde_new(d):
    name = re.sub(r'[<>:"/\\|?*]', '', (d.get('name') or '')).strip()
    if not name:
        return {'error': 'Name fehlt'}
    slug = re.sub(r'-+', '-', name.lower().replace(' ', '-')).strip('-')   # Kundenordner in Kleinschreibung
    if not slug.strip('.'):                                     # `..` waere ein Weg aus 02_kunden hinaus
        return {'error': 'Name fehlt'}
    path = os.path.join(VAULT, '02_kunden', slug, slug + '.md')
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        return {'error': 'Kunde existiert schon'}
    text = ('---\ntyp: kunde\nstatus: aktiv\nseit: %s\nzugewiesen_an: \nki_freigabe: gesperrt\n---\n\n'
            '# Übersicht — %s\n\n- **Kunde:** %s\n- Onboarding ausstehend\n'
            % (time.strftime('%Y-%m-%d'), name, name))
    r = write_file(path, text)
    r.setdefault('path', '02_kunden/' + slug + '/' + slug + '.md')
    return r

# ---------- Plugin-Erkennung (oeffentliches HTML, nur bekannte Sites) ----------
PLUG = {}

def api_plugins(url):
    if url not in set(all_sites().values()):
        return {'error': 'unbekannte Site'}
    hit = PLUG.get(url)
    if hit and time.time() - hit['ts'] < 3600:
        return hit['res']
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 puox-monitor'})
        html = urllib.request.urlopen(req, timeout=10).read(400000).decode('utf-8', 'replace')
        res = {'plugins': sorted({m.lower() for m in re.findall(r'wp-content/plugins/([A-Za-z0-9_.-]+)', html)}),
               'themes': sorted({m for m in re.findall(r'wp-content/themes/([A-Za-z0-9_.-]+)', html)}),
               'hinweis': 'Erkannt aus dem öffentlichen HTML (eingebundene Assets). Tiefer Check '
                          '(aktiv/konfiguriert/Updates) braucht WP-Zugang.'}
    except Exception as e:
        res = {'error': '%s' % e}
    PLUG[url] = {'ts': time.time(), 'res': res}
    return res

# ---------- Chat + /db-update (headless claude -p) ----------
JOBS = {}

def start_job(agent, args, cwd):
    jid = uuid.uuid4().hex[:8]
    JOBS[jid] = {'agent': agent, 'status': 'running', 'output': '', 't0': time.time()}
    def w():
        try:
            out, err, rc = run(args, cwd=cwd, timeout=3600)
            JOBS[jid].update(status='done' if rc == 0 else 'error',
                             output=(out.strip() or err.strip() or '(keine Ausgabe)'))
        except Exception as e:
            JOBS[jid].update(status='error', output='%s: %s' % (e.__class__.__name__, e))
    threading.Thread(target=w, daemon=True).start()
    return {'id': jid}

def api_chat_start(d):
    agent = re.sub(r'[^\w-]', '', d.get('agent') or '')
    if not agent or not (d.get('text') or '').strip():
        return {'error': 'Agent/Text fehlt'}
    cwd = os.path.join(BASE, 'agenten') if d.get('env') == 'pipeline' else VAULT
    prompt = "Nutze den Agenten '%s' fuer diese Aufgabe und gib nur sein Ergebnis zurueck: %s" % (agent, d['text'])
    return start_job(agent, [CLAUDE, '-p', prompt, '--output-format', 'text'], cwd)

def api_dbupdate(d):
    if any(j['agent'] == 'sage' and j['status'] == 'running' for j in JOBS.values()):
        return {'error': 'DB-Update laeuft schon'}
    return start_job('sage', [CLAUDE, '-p', '/db-update', '--output-format', 'text',
                              '--permission-mode', 'acceptEdits'], VAULT)

def api_gitcommit(d):
    if any(j['agent'] == 'git' and j['status'] == 'running' for j in JOBS.values()):
        return {'error': 'Git-Agent laeuft schon'}
    prompt = ('Committe den aktuellen Vault-Stand: 1) git status --short pruefen; bei ploetzlichen '
              'Massen-Loeschungen abbrechen und melden. '
              '2) Sonst git add -A und EIN Commit mit kurzer deutscher Zusammenfassung der Aenderungen '
              '(Versionierungs-Regeln des Vaults beachten). Nicht pushen. '
              'Gib nur das Ergebnis zurueck.')
    return start_job('git', [CLAUDE, '-p', prompt, '--output-format', 'text',
                             '--permission-mode', 'acceptEdits'], VAULT)

def api_status():
    ag = {}
    for j in JOBS.values():
        a = j['agent']
        if j['status'] == 'running':
            ag[a] = 'aktiv'
        elif j['status'] == 'error' and ag.get(a) != 'aktiv' and time.time() - j['t0'] < 600:
            ag[a] = 'fehler'
    sj = os.path.join(BASE, 'status.json')  # optionaler externer Status
    if os.path.isfile(sj):
        try:
            for k, v in (json.load(open(sj, encoding='utf-8')).get('agents') or {}).items():
                ag.setdefault(k, v)
        except Exception:
            pass
    return {'agents': ag}

# ---------- Mail (E-Mail-Client, Sperrzone 97_puoxos/secrets/) ----------
# Zugangsdaten liegen DPAPI-verschluesselt (an dieses Windows-Benutzerkonto gebunden) in
# 97_puoxos/secrets/mail.json. Kein Postfach-Cache auf Platte -- jede Ansicht holt live per IMAP.
# Bis zu MAX_ACCOUNTS ganz normale IMAP/SMTP-Postfaecher (kein Provider-Sonderfall), EIN Mail-PIN
# schuetzt den gesamten Mail-Tab. Zusaetzlich PIN-Sitzungstoken vor jedem /api/mail/*-Zugriff
# (Ziel: hohe Sicherheit).
import base64, ctypes, ctypes.wintypes as wt, hashlib, hmac, imaplib, secrets, smtplib
import email as email_lib, email.utils, email.header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders as email_encoders

MAIL_DIR  = os.path.join(BASE, 'secrets')
MAIL_FILE = os.path.join(MAIL_DIR, 'mail.json')
MAIL_SESSIONS = {}            # token -> Ablauf-Timestamp
MAIL_SESSION_TTL = 12 * 3600
MAX_ACCOUNTS = 5

class _DATA_BLOB(ctypes.Structure):
    _fields_ = [('cbData', wt.DWORD), ('pbData', ctypes.POINTER(ctypes.c_char))]

_crypt32 = ctypes.WinDLL('crypt32.dll')
_kernel32 = ctypes.WinDLL('kernel32.dll')
_crypt32.CryptProtectData.argtypes = [ctypes.POINTER(_DATA_BLOB), wt.LPCWSTR, ctypes.POINTER(_DATA_BLOB),
                                       wt.LPVOID, wt.LPVOID, wt.DWORD, ctypes.POINTER(_DATA_BLOB)]
_crypt32.CryptProtectData.restype = wt.BOOL
_crypt32.CryptUnprotectData.argtypes = [ctypes.POINTER(_DATA_BLOB), ctypes.POINTER(wt.LPWSTR), ctypes.POINTER(_DATA_BLOB),
                                         wt.LPVOID, wt.LPVOID, wt.DWORD, ctypes.POINTER(_DATA_BLOB)]
_crypt32.CryptUnprotectData.restype = wt.BOOL
_kernel32.LocalFree.argtypes = [wt.HLOCAL]

def _dpapi_blob(data):
    buf = ctypes.create_string_buffer(data, len(data))
    return _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

def dpapi_protect(data: bytes) -> bytes:
    inb, _keep = _dpapi_blob(data)
    outb = _DATA_BLOB()
    if not _crypt32.CryptProtectData(ctypes.byref(inb), None, None, None, None, 0, ctypes.byref(outb)):
        raise OSError('CryptProtectData fehlgeschlagen: %s' % ctypes.WinError())
    try:
        return ctypes.string_at(outb.pbData, outb.cbData)
    finally:
        _kernel32.LocalFree(outb.pbData)

def dpapi_unprotect(data: bytes) -> bytes:
    inb, _keep = _dpapi_blob(data)
    outb = _DATA_BLOB()
    if not _crypt32.CryptUnprotectData(ctypes.byref(inb), None, None, None, None, 0, ctypes.byref(outb)):
        raise OSError('CryptUnprotectData fehlgeschlagen: %s' % ctypes.WinError())
    try:
        return ctypes.string_at(outb.pbData, outb.cbData)
    finally:
        _kernel32.LocalFree(outb.pbData)

# ---------- Kalender-Logins (dieselbe Sperrzone 97_puoxos/secrets/) ----------
# Mehrere ICS/CalDAV-Kalender per Benutzername+Passwort (Basic/Digest auf die URL). Kein volles
# CalDAV-Browsing -- eine URL je Kalender, bewusst so.
KAL_FILE = os.path.join(MAIL_DIR, 'kalender.json')
KAL_FARBEN = ['#66B8FF', '#FFC24D', '#B18CFF', '#4DD9E8', '#FF8FB1', '#A3E635']

def kal_liste():
    """Immer eine Liste. Altbestand (ein einzelnes dict) wird beim Lesen mitgewandelt."""
    if not os.path.isfile(KAL_FILE):
        return []
    # Fail-closed wie termine_laden: ein Lesefehler (kaputt, vom Virenscanner gesperrt) darf nicht als
    # "keine Kalender" gelten, sonst ueberschreibt das naechste kal_save alle Zugaenge.
    try:
        d = json.load(open(KAL_FILE, encoding='utf-8'))
    except Exception as e:
        raise RuntimeError('kalender.json unlesbar (%s) -- nichts gespeichert' % e.__class__.__name__)
    if not isinstance(d, (dict, list)):
        raise RuntimeError('kalender.json unlesbar (kein Objekt/keine Liste) -- nichts gespeichert')
    if isinstance(d, dict):
        d = [dict(d, id='kal1', name=d.get('name') or 'Kalender', farbe=KAL_FARBEN[0], an=True)]
    for i, k in enumerate(d):
        k.setdefault('id', 'kal%d' % (i + 1))
        k.setdefault('name', 'Kalender %d' % (i + 1))
        k.setdefault('farbe', KAL_FARBEN[i % len(KAL_FARBEN)])
        k.setdefault('an', True)
    return d

def kal_data():
    """Der Hauptkalender (Einstellungen) bzw. der erste -- fuer Einzelabfragen."""
    liste = kal_liste()
    if not liste:
        return None
    haupt = api_theme().get('hauptkalender') or ''
    return next((k for k in liste if k['id'] == haupt), liste[0])

def kal_save(data):
    os.makedirs(MAIL_DIR, exist_ok=True)
    write_file(KAL_FILE, json.dumps(data, ensure_ascii=False, indent=2))

def kal_password(kal):
    return dpapi_unprotect(base64.b64decode(kal['password_enc'])).decode('utf-8') if kal.get('password_enc') else ''

CALDAV_REPORT = ('<?xml version="1.0" encoding="utf-8"?>'
                 '<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">'
                 '<d:prop><c:calendar-data/></d:prop>'
                 '<c:filter><c:comp-filter name="VCALENDAR">'
                 '<c:comp-filter name="VEVENT"/></c:comp-filter></c:filter>'
                 '</c:calendar-query>')

def _opener(username, password):
    """Basic UND Digest: reines preemptives Basic scheitert an Servern, die Digest verlangen (401)."""
    mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    mgr.add_password(None, 'https://', username, password)
    mgr.add_password(None, 'http://', username, password)
    return urllib.request.build_opener(urllib.request.HTTPBasicAuthHandler(mgr),
                                       urllib.request.HTTPDigestAuthHandler(mgr))

def _http(url, username, password, method='GET', body=None, headers=None):
    req = urllib.request.Request(url, data=body.encode('utf-8') if body else None, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    if username:  # preemptiv mitschicken -- viele Server antworten sonst gar nicht erst mit Challenge
        tok = base64.b64encode(('%s:%s' % (username, password)).encode('utf-8')).decode('ascii')
        req.add_header('Authorization', 'Basic %s' % tok)
    op = _opener(username, password) if username else urllib.request.build_opener()
    return op.open(req, timeout=15).read().decode('utf-8', 'replace')

def _fetch_ics(url, username='', password=''):
    """Erst normaler GET (ICS-Datei-Link). Liefert der Server kein ICS oder verweigert er den GET,
    wird es als CalDAV-Kalender per REPORT versucht -- viele Hoster sprechen genau das."""
    try:
        raw = _http(url, username, password)
        if 'BEGIN:VCALENDAR' in raw or 'BEGIN:VEVENT' in raw:
            return raw
        first_err = 'Antwort war kein ICS (%d Zeichen)' % len(raw)
    except urllib.error.HTTPError as e:
        if e.code == 401:
            scheme = (e.headers.get('WWW-Authenticate') or '').split(' ')[0] or 'unbekannt'
            first_err = 'Login abgelehnt (401, Verfahren: %s)' % scheme
        else:
            first_err = 'HTTP %s' % e.code
    except Exception as e:
        first_err = '%s' % e
    try:
        xml = _http(url, username, password, method='REPORT', body=CALDAV_REPORT,
                    headers={'Depth': '1', 'Content-Type': 'application/xml; charset=utf-8'})
    except Exception as e:
        raise RuntimeError('%s; CalDAV-REPORT ebenfalls fehlgeschlagen: %s' % (first_err, e))
    ics = caldav_to_ics(xml)
    if not ics:
        raise RuntimeError('%s; CalDAV-REPORT lieferte keine Termine' % first_err)
    return ics

def caldav_to_ics(xml):
    """calendar-data-Bloecke aus einer CalDAV-REPORT-Antwort zu einem ICS zusammenkleben."""
    teile = re.findall(r'<[^>]*calendar-data[^>]*>(.*?)</[^>]*calendar-data>', xml, re.S)
    ent = [('&lt;', '<'), ('&gt;', '>'), ('&quot;', '"'), ('&#13;', ''), ('&amp;', '&')]
    out = []
    for t in teile:
        for a, b in ent:
            t = t.replace(a, b)
        t = t.strip()
        if t:
            out.append(t)
    return '\n'.join(out)

def api_kalender_status():
    liste = kal_liste()
    return {'configured': bool(liste),
            'kalender': [{'id': k['id'], 'name': k['name'], 'url': k.get('url', ''),
                          'username': k.get('username', ''), 'farbe': k['farbe'], 'an': bool(k.get('an', True))}
                         for k in liste]}

def api_kalender_setup(d):
    """Legt an oder aendert (wenn `id` mitkommt). Leeres Passwort bei Aenderung = unveraendert."""
    url = (d.get('url') or '').strip().replace('webcal://', 'https://')
    username = (d.get('username') or '').strip()
    password = d.get('password') or ''
    if not url:
        return {'error': 'Kalender-URL fehlt'}
    liste = kal_liste()
    alt = next((k for k in liste if k['id'] == d.get('id')), None)
    if not alt and len(liste) >= 8:
        return {'error': 'Maximal 8 Kalender'}
    if not password and alt and alt.get('password_enc'):
        # Gespeichertes Passwort nur an die gespeicherte URL -- sonst liesse es sich an jeden Server umleiten
        if url != alt.get('url'):
            return {'error': 'Neue Adresse — Zugangsdaten neu eingeben'}
        password = kal_password(alt)
    try:
        raw = _fetch_ics(url, username, password)
    except Exception as e:
        return {'error': 'Verbindung fehlgeschlagen: %s' % e}
    if 'BEGIN:VCALENDAR' not in raw and 'BEGIN:VEVENT' not in raw:
        return {'error': 'Antwort sieht nicht wie ein ICS-Kalender aus -- URL/Login pruefen'}
    eintrag = alt or {'id': 'kal%s' % uuid.uuid4().hex[:6], 'farbe': KAL_FARBEN[len(liste) % len(KAL_FARBEN)]}
    eintrag.update({'url': url, 'username': username, 'an': bool(d.get('an', True)),
                    'name': (d.get('name') or '').strip()[:60] or eintrag.get('name') or 'Kalender %d' % (len(liste) + 1)})
    if d.get('farbe') and HEX_RE.match(d['farbe']):
        eintrag['farbe'] = d['farbe']
    if password:
        eintrag['password_enc'] = base64.b64encode(dpapi_protect(password.encode('utf-8'))).decode('ascii')
    if not alt:
        liste.append(eintrag)
    kal_save(liste)
    TERM.update(ts=0, evs=None, err='')  # Cache invalidieren, naechster Abruf laedt frisch
    return {'ok': True, 'id': eintrag['id']}

def api_kalender_toggle(d):
    liste = kal_liste()
    k = next((x for x in liste if x['id'] == d.get('id')), None)
    if not k:
        return {'error': 'Kalender nicht gefunden'}
    k['an'] = bool(d.get('an'))
    kal_save(liste)
    TERM.update(ts=0, evs=None, err='')
    return {'ok': True}

def api_kalender_remove(d):
    liste = kal_liste()
    neu = [k for k in liste if k['id'] != d.get('id')]
    if len(neu) == len(liste):   # unbekannte/fehlende id: Fehler -- frueher loeschte das ALLE Kalender
        return {'error': 'Kalender nicht gefunden'}
    kal_save(neu)
    TERM.update(ts=0, evs=None, err='')
    return {'ok': True}

# ---- IMAP Modified-UTF-7 (Ordnernamen mit Umlauten etc.) ----
def imap_utf7_encode(s):
    res, i, n = [], 0, len(s)
    while i < n:
        c = s[i]
        if c == '&':
            res.append('&-'); i += 1
        elif 0x20 <= ord(c) <= 0x7e:
            res.append(c); i += 1
        else:
            j = i
            while j < n and not (0x20 <= ord(s[j]) <= 0x7e):
                j += 1
            b64 = base64.b64encode(s[i:j].encode('utf-16-be')).decode('ascii').rstrip('=').replace('/', ',')
            res.append('&' + b64 + '-'); i = j
    return ''.join(res)

def imap_utf7_decode(s):
    if isinstance(s, bytes):
        s = s.decode('ascii')
    res, i = [], 0
    while i < len(s):
        c = s[i]
        if c == '&':
            j = s.find('-', i + 1)
            if j == -1: j = len(s)
            chunk = s[i + 1:j]
            if chunk == '':
                res.append('&')
            else:
                chunk = chunk.replace(',', '/')
                b = base64.b64decode(chunk + '=' * (-len(chunk) % 4))
                res.append(b.decode('utf-16-be'))
            i = j + 1
        else:
            res.append(c); i += 1
    return ''.join(res)

def _mbox(name):
    return '"%s"' % imap_utf7_encode(name).replace('\\', '\\\\').replace('"', '\\"')

def _dek(b, zs):
    """Bytes -> Text. Unbekannter oder von Python nicht decodierbarer Zeichensatz (auch
    'unknown-8bit' bei rohen 8-Bit-Koepfen, Codecs wie 'undefined'/'idna', die selbst mit
    errors='replace' noch werfen, oder ein Zeichensatzname mit NUL-Byte -- ValueError statt
    UnicodeError) faellt auf UTF-8 zurueck, statt die ganze Nachrichtenliste zu kippen."""
    try:
        return b.decode(zs or 'utf-8', 'replace')
    except (LookupError, ValueError):   # UnicodeError ist eine Unterklasse von ValueError
        return b.decode('utf-8', 'replace')

def _decode_hdr(raw):
    if not raw:
        return ''
    try:
        teile = email.header.decode_header(raw)
    except Exception:            # kaputtes Base64/QP im encoded-word: Kopf roh zeigen
        return str(raw)
    return ''.join(_dek(txt, enc) if isinstance(txt, bytes) else txt for txt, enc in teile)

# Mail-PIN: Ziffern UND Buchstaben, 4 bis 32 Zeichen. \A…\Z statt ^…$ -- sonst kaeme "1234\n" durch.
# Bewusst kein Sonderzeichen-Zwang: die PIN schuetzt einen lokalen Tab, nicht das Postfach selbst.
PIN_RE = re.compile(r'\A[^\s\x00-\x1f]{4,32}\Z')

def _pin_hash(pin, salt):
    return hashlib.pbkdf2_hmac('sha256', pin.encode('utf-8'), salt, 200_000).hex()

def mail_data():
    if not os.path.isfile(MAIL_FILE):
        return None
    return json.load(open(MAIL_FILE, encoding='utf-8'))

def mail_save(data):
    os.makedirs(MAIL_DIR, exist_ok=True)
    write_file(MAIL_FILE, json.dumps(data, ensure_ascii=False, indent=2))

def mail_account_by_id(data, aid):
    return next((a for a in (data or {}).get('accounts', []) if a['id'] == aid), None)

def mail_password(acc):
    return dpapi_unprotect(base64.b64decode(acc['password_enc'])).decode('utf-8')

def mail_new_token():
    tok = secrets.token_urlsafe(32)
    MAIL_SESSIONS[tok] = time.time() + MAIL_SESSION_TTL
    return tok

def mail_check(token):
    exp = MAIL_SESSIONS.get(token or '')
    if not exp or exp < time.time():
        return False
    MAIL_SESSIONS[token] = time.time() + MAIL_SESSION_TTL
    return True

def _connect_imap(host, port, use_ssl=True):
    return imaplib.IMAP4_SSL(host, port, timeout=15) if use_ssl else imaplib.IMAP4(host, port, timeout=15)

def _connect_smtp(host, port, mode='starttls'):
    if mode == 'ssl':
        return smtplib.SMTP_SSL(host, port, timeout=15)
    sm = smtplib.SMTP(host, port, timeout=15)
    sm.starttls()
    return sm

def _imap_login(acc):
    im = _connect_imap(acc['imap_host'], acc['imap_port'], acc.get('imap_ssl', True))
    im.login(acc['email'], mail_password(acc))
    return im

def _imap(account_id):
    data = mail_data()
    if not data:
        raise RuntimeError('kein E-Mail-Konto eingerichtet')
    acc = mail_account_by_id(data, account_id)
    if not acc:
        raise RuntimeError('unbekanntes Postfach')
    return _imap_login(acc), acc

# ---------- IMAP/SMTP automatisch finden ----------
# Reihenfolge: Mozilla-ISPDB (kennt fast jeden Anbieter) -> autoconfig.<domain> -> gaengige Namen
# per echtem Verbindungstest. Ohne Zugangsdaten -- geprobt wird nur, ob der Port TLS spricht.
AUTOCONF_ISPDB = 'https://autoconfig.thunderbird.net/v1.1/%s'
AUTOCONF_LOKAL = ('https://autoconfig.%s/mail/config-v1.1.xml', 'http://autoconfig.%s/mail/config-v1.1.xml')

def _autoconf_xml(domain):
    for url in (AUTOCONF_ISPDB % domain,) + tuple(u % domain for u in AUTOCONF_LOKAL):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'puox-os'})
            with urllib.request.urlopen(req, timeout=6) as r:
                roh = r.read(200_000).decode('utf-8', errors='replace')
            if '<incomingServer' in roh:
                return roh
        except Exception:
            continue
    return ''

def _autoconf_aus_xml(xml):
    """Nimmt je Richtung den ersten passenden Server (ISPDB listet den empfohlenen zuerst)."""
    raus = {}
    for block, typ in ((r'<incomingServer\b[^>]*type="imap".*?</incomingServer>', 'imap'),
                       (r'<outgoingServer\b[^>]*type="smtp".*?</outgoingServer>', 'smtp')):
        m = re.search(block, xml, re.S | re.I)
        if not m:
            continue
        teil = m.group(0)
        host = re.search(r'<hostname>\s*([^<\s]+)\s*</hostname>', teil, re.I)
        port = re.search(r'<port>\s*(\d+)\s*</port>', teil, re.I)
        sock = re.search(r'<socketType>\s*([^<\s]+)\s*</socketType>', teil, re.I)
        if host and port:
            raus[typ] = {'host': host.group(1), 'port': int(port.group(1)),
                         'ssl': (sock.group(1).upper() if sock else 'SSL')}
    return raus

def _port_spricht(host, port, ssl_direkt, imap):
    try:
        if imap:
            c = _connect_imap(host, port, ssl_direkt)
            c.logout()
        else:
            c = _connect_smtp(host, port, 'ssl' if ssl_direkt else 'starttls')
            c.quit()
        return True
    except Exception:
        return False

def api_mail_autoconfig(email_addr):
    """Sucht IMAP/SMTP-Host, Port und Verschluesselung zu einer Adresse. Nie ein Passwort im Spiel."""
    email_addr = (email_addr or '').strip()
    if '@' not in email_addr:
        return {'error': 'Bitte zuerst die vollstaendige E-Mail-Adresse eintragen'}
    domain = email_addr.rsplit('@', 1)[1].lower()
    if not re.match(r'\A[a-z0-9.\-]{3,80}\Z', domain):
        return {'error': 'Domain unbrauchbar'}
    gefunden = _autoconf_aus_xml(_autoconf_xml(domain))
    raus, quelle = {}, 'autoconfig'
    if gefunden.get('imap'):
        i = gefunden['imap']
        raus.update(imap_host=i['host'], imap_port=i['port'], imap_ssl=i['ssl'] != 'STARTTLS')
    if gefunden.get('smtp'):
        s = gefunden['smtp']
        raus.update(smtp_host=s['host'], smtp_port=s['port'],
                    smtp_mode='ssl' if s['ssl'] == 'SSL' else 'starttls')
    if 'imap_host' not in raus:      # Raten + echter Verbindungstest
        quelle = 'test'
        for h in ('imap.%s' % domain, 'mail.%s' % domain, 'imap.mail.%s' % domain, domain):
            if _port_spricht(h, 993, True, True):
                raus.update(imap_host=h, imap_port=993, imap_ssl=True); break
            if _port_spricht(h, 143, False, True):
                raus.update(imap_host=h, imap_port=143, imap_ssl=False); break
    if 'smtp_host' not in raus:
        quelle = 'test' if 'imap_host' in raus else quelle
        for h in ('smtp.%s' % domain, 'mail.%s' % domain, 'smtp.mail.%s' % domain, domain):
            if _port_spricht(h, 587, False, False):
                raus.update(smtp_host=h, smtp_port=587, smtp_mode='starttls'); break
            if _port_spricht(h, 465, True, False):
                raus.update(smtp_host=h, smtp_port=465, smtp_mode='ssl'); break
    if not raus:
        return {'error': 'Nichts gefunden fuer %s — Server bitte von Hand eintragen' % domain}
    raus['quelle'] = quelle
    raus['unvollstaendig'] = not ('imap_host' in raus and 'smtp_host' in raus)
    return raus

def _build_account(d):
    email_addr = (d.get('email') or '').strip()
    password   = d.get('password') or ''
    imap_host  = (d.get('imap_host') or '').strip()
    smtp_host  = (d.get('smtp_host') or '').strip()
    label      = (d.get('label') or '').strip() or email_addr
    try:
        imap_port = int(d.get('imap_port') or 993)
        smtp_port = int(d.get('smtp_port') or 587)
    except (TypeError, ValueError):
        return None, 'Port muss eine Zahl sein'
    imap_ssl  = bool(d.get('imap_ssl', True))
    smtp_mode = d.get('smtp_mode') or 'starttls'
    if not (email_addr and password and imap_host and smtp_host):
        return None, 'Bitte alle Felder ausfuellen'
    try:
        im = _connect_imap(imap_host, imap_port, imap_ssl)
        im.login(email_addr, password); im.logout()
    except Exception as e:
        return None, 'IMAP-Login fehlgeschlagen: %s' % e
    try:
        sm = _connect_smtp(smtp_host, smtp_port, smtp_mode)
        sm.login(email_addr, password); sm.quit()
    except Exception as e:
        return None, 'SMTP-Login fehlgeschlagen: %s' % e
    return {'id': secrets.token_hex(4), 'label': label, 'email': email_addr,
            'imap_host': imap_host, 'imap_port': imap_port, 'imap_ssl': imap_ssl,
            'smtp_host': smtp_host, 'smtp_port': smtp_port, 'smtp_mode': smtp_mode,
            'password_enc': base64.b64encode(dpapi_protect(password.encode('utf-8'))).decode('ascii')}, None

# ---------- Mail: API ----------
def api_mail_status():
    data = mail_data()
    accs = [{'id': a['id'], 'email': a['email'], 'label': a['label']} for a in (data or {}).get('accounts', [])]
    return {'configured': bool(data), 'accounts': accs, 'maxAccounts': MAX_ACCOUNTS}

def api_mail_setup(d):
    # Ein eingerichtetes Mail (PIN + Postfaecher) nur mit gueltigem Mail-Token neu aufsetzen --
    # sonst setzt jede angemeldete Sitzung den Mail-PIN neu und verwirft alle Postfaecher.
    if mail_data() and not mail_check(d.get('token')):
        return {'error': 'gesperrt', 'auth': True}
    pin = d.get('pin') or ''
    if not PIN_RE.match(pin):
        return {'error': 'PIN: 4 bis 32 Zeichen (Ziffern und Buchstaben)'}
    acc, err = _build_account(d)
    if err:
        return {'error': err}
    salt = secrets.token_bytes(16)
    mail_save({'pin_salt': salt.hex(), 'pin_hash': _pin_hash(pin, salt), 'accounts': [acc]})
    return {'ok': True, 'token': mail_new_token()}

def api_mail_unlock(d, ip='?'):
    data = mail_data()
    if not data:
        return {'error': 'Kein Konto eingerichtet'}
    # Formatpruefung zuerst: die Auto-Anmeldung fragt still an (nach 600 ms Tipp-Pause), pbkdf2 kostet ~150 ms
    if not PIN_RE.match(d.get('pin') or ''):
        return {'error': 'PIN: 4 bis 32 Zeichen (Ziffern und Buchstaben)'}
    bremse = pin_bremse('mail ' + ip)   # eigener Zaehler: Mail-PIN ist nicht die Zugangs-PIN
    if bremse:
        return {'error': bremse}
    salt = bytes.fromhex(data['pin_salt'])
    if not hmac.compare_digest(_pin_hash(d.get('pin') or '', salt), data['pin_hash']):
        return {'error': 'Falsche PIN'}
    ZUGANG_VERSUCHE.pop('mail ' + ip, None)
    return {'ok': True, 'token': mail_new_token()}

def api_mail_lock(d):
    MAIL_SESSIONS.pop(d.get('token') or '', None)
    return {'ok': True}

def api_mail_account_add(d):
    if not mail_check(d.get('token')):
        return {'error': 'gesperrt', 'auth': True}
    data = mail_data()
    if not data:
        return {'error': 'Kein Konto eingerichtet'}
    if len(data.get('accounts', [])) >= MAX_ACCOUNTS:
        return {'error': 'Maximal %d Postfächer' % MAX_ACCOUNTS}
    acc, err = _build_account(d)
    if err:
        return {'error': err}
    data['accounts'].append(acc)
    mail_save(data)
    return {'ok': True, 'account': {'id': acc['id'], 'email': acc['email'], 'label': acc['label']}}

def api_mail_account_remove(d):
    if not mail_check(d.get('token')):
        return {'error': 'gesperrt', 'auth': True}
    data = mail_data()
    if not data:
        return {'error': 'Kein Konto eingerichtet'}
    data['accounts'] = [a for a in data.get('accounts', []) if a['id'] != d.get('id')]
    mail_save(data)
    return {'ok': True}

def _folders_roh(im):
    """LIST auswerten: Name, Rohname, Flags und das Trennzeichen fuer die Unterordner-Ebene."""
    typ, data = im.list()
    out = []
    for line in data or []:
        if not line:
            continue
        s = line.decode('utf-8', 'replace') if isinstance(line, bytes) else line
        m = re.match(r'\((?P<flags>[^)]*)\)\s+"?(?P<delim>[^"\s]*)"?\s+(?P<name>.+)', s)
        if not m:
            continue
        raw_name = m.group('name').strip().strip('"')
        out.append({'name': imap_utf7_decode(raw_name), 'raw': raw_name,
                    'flags': m.group('flags'), 'delim': m.group('delim') or '/'})
    return out

def _alle_abonnieren(im):
    """Jeder Ordner wird abonniert -- der Baum zeigt sonst je nach Server nur einen Teil."""
    n = 0
    for f in _folders_roh(im):
        if '\\Noselect' in f['flags']:
            continue
        try:
            if im.subscribe(_mbox(f['name']))[0] == 'OK':
                n += 1
        except Exception:
            pass
    return n

def api_mail_folders(token, account_id):
    if not mail_check(token):
        return {'error': 'gesperrt', 'auth': True}
    im, acc = _imap(account_id)
    try:
        out = _folders_roh(im)
        order = {'Inbox': 0, 'Sent': 1, 'Drafts': 2, 'Archive': 3, 'Junk': 4, 'Trash': 5}
        # Sortierung: Sonderordner zuerst, danach alphabetisch je Ebene -- so stehen Unterordner
        # direkt unter ihrem Elternordner statt verstreut.
        def key(f):
            rang = order.get(next((k for k in order if '\\' + k in f['flags']), ''), 9)
            return (rang, f['name'].lower())
        out.sort(key=key)
        for f in out:
            d = f.get('delim') or '/'
            teile = f['name'].split(d) if d else [f['name']]
            f['tiefe'] = len(teile) - 1
            f['kurz'] = teile[-1]
            f['eltern'] = d.join(teile[:-1])
            f['auswaehlbar'] = '\\Noselect' not in f['flags']
            f['abonniert'] = True   # Abos werden beim Abgleich gesetzt, kein Filter mehr in der Anzeige
        return {'folders': out}
    finally:
        im.logout()

def api_mail_folder(d):
    """Ordner anlegen / umbenennen / loeschen / abonnieren -- ein Endpunkt, `op` entscheidet."""
    if not mail_check(d.get('token')):
        return {'error': 'gesperrt', 'auth': True}
    op, name = d.get('op'), (d.get('name') or '').strip()
    if not name:
        return {'error': 'Ordnername fehlt'}
    im, acc = _imap(d.get('account'))
    try:
        if op == 'create':
            typ, r = im.create(_mbox(name))
            if typ == 'OK':
                im.subscribe(_mbox(name))
        elif op == 'rename':
            neu = (d.get('neu') or '').strip()
            if not neu:
                return {'error': 'Neuer Name fehlt'}
            typ, r = im.rename(_mbox(name), _mbox(neu))
            if typ == 'OK':
                try:
                    im.unsubscribe(_mbox(name))
                    im.subscribe(_mbox(neu))
                except Exception:
                    pass
        elif op == 'delete':
            typ, r = im.delete(_mbox(name))
        elif op == 'subscribe':
            typ, r = (im.subscribe if d.get('an') else im.unsubscribe)(_mbox(name))
        else:
            return {'error': 'unbekannte Aktion'}
        if typ != 'OK':
            return {'error': (r[0].decode('utf-8', 'replace') if r and r[0] else 'Server hat abgelehnt')}
        return {'ok': True}
    finally:
        im.logout()

# ---------- Mail: Einstellungen je Postfach (Signatur, Autoresponder) ----------
# Region/Zeitzone und das Abgleich-Intervall stehen NICHT mehr hier, sondern global in theme.json
# (Einstellungen -> Zeit & Region bzw. -> Abgleich). Sie werden hier nur noch eingemischt, damit
# alle Aufrufer weiter ein vollstaendiges prefs-Objekt bekommen.
MAIL_PREFS_DEFAULT = {'signatur': '', 'auto_an': False, 'auto_betreff': 'Automatische Antwort',
                      'auto_text': ''}
MAIL_PREFS_GLOBAL = ('region', 'tz', 'poll_stunden')

def _prefs(data, aid):
    p = dict(MAIL_PREFS_DEFAULT)
    p.update({k: v for k, v in ((data.get('prefs') or {}).get(aid) or {}).items()
              if k in MAIL_PREFS_DEFAULT})
    th = api_theme()
    p['region'] = th.get('region') or 'de-DE'
    p['tz'] = th.get('zeitzone') or 'Europe/Berlin'
    p['poll_stunden'] = th.get('mail_poll_stunden') or 24
    return p

def api_mail_prefs(token, account_id):
    if not mail_check(token):
        return {'error': 'gesperrt', 'auth': True}
    return {'prefs': _prefs(mail_data() or {}, account_id)}

def api_mail_prefs_save(d):
    if not mail_check(d.get('token')):
        return {'error': 'gesperrt', 'auth': True}
    data = mail_data()
    if not data:
        return {'error': 'Kein Konto eingerichtet'}
    aid = d.get('account')
    if not mail_account_by_id(data, aid):
        return {'error': 'Postfach unbekannt'}
    p = _prefs(data, aid)
    for k in MAIL_PREFS_DEFAULT:
        if k in d:
            p[k] = d[k]
    # nur die postfach-eigenen Felder wandern in die Datei -- Region/Abgleich sind global
    data.setdefault('prefs', {})[aid] = {k: p[k] for k in MAIL_PREFS_DEFAULT}
    mail_save(data)
    return {'ok': True, 'prefs': p}

# ---------- Mail: Hintergrund-Abgleich + Autoresponder ----------
MAIL_POLL = {'ts': 0, 'letzte': {}, 'laeuft': False}

def auto_antworten_erlaubt(kopf, absender, eigene, log, jetzt, sperre_h=24):
    """Autoresponder-Regeln: keine Schleifen, keine Listen, ein Absender hoechstens alle sperre_h."""
    if not absender or '@' not in absender:
        return False
    low = absender.lower()
    if low in {e.lower() for e in eigene}:
        return False
    h = {k.lower(): (v or '') for k, v in kopf.items()}
    if h.get('auto-submitted', 'no').lower() not in ('', 'no'):
        return False
    if h.get('precedence', '').lower() in ('bulk', 'list', 'junk'):
        return False
    if h.get('list-id') or h.get('list-unsubscribe') or h.get('x-auto-response-suppress'):
        return False
    if h.get('return-path', '').strip() in ('<>', ''):
        if h.get('return-path'):
            return False
    return jetzt - log.get(low, 0) >= sperre_h * 3600

def mail_poll_einmal():
    """Neue Nachrichten je abonniertem Postfach zaehlen und ggf. Autoresponder ausloesen."""
    data = mail_data()
    if not data:
        return {}
    jetzt, out = time.time(), {}
    log = data.setdefault('auto_log', {})
    geaendert = False
    for acc in data.get('accounts', []):
        p = _prefs(data, acc['id'])
        try:
            im = _imap_login(acc)
        except Exception as e:
            out[acc['id']] = {'error': '%s' % e}
            continue
        try:
            im.select('INBOX', readonly=not p['auto_an'])
            typ, res = im.uid('search', None, 'UNSEEN')
            uids = res[0].split() if typ == 'OK' and res and res[0] else []
            out[acc['id']] = {'neu': len(uids)}
            if not p['auto_an'] or not p['auto_text']:
                continue
            eigene = [a['email'] for a in data.get('accounts', [])]
            for uid in uids[-20:]:  # Deckel bei 20 -- ein Rueckstau darf keine Mailflut ausloesen
                typ, dd = im.uid('fetch', uid, '(BODY.PEEK[HEADER])')
                if typ != 'OK' or not dd or not isinstance(dd[0], tuple):
                    continue
                msg = _mail_parse(dd[0][1])
                if msg is None:
                    continue  # Kopf nicht lesbar (z.B. boundary*=undefined''X) -- nur DIESE Mail
                              # ueberspringen; {'neu': n} oben bleibt stehen, andere ungelesene Mails
                              # bekommen trotzdem ihre Autoantwort
                absender = email.utils.parseaddr(msg.get('From', ''))[1]
                if not auto_antworten_erlaubt(dict(msg.items()), absender, eigene, log, jetzt):
                    continue
                _auto_reply(acc, p, absender, _decode_hdr(msg.get('Subject', '')), msg.get('Message-Id', ''))
                log[absender.lower()] = jetzt
                geaendert = True
        except Exception as e:
            out[acc['id']] = {'error': '%s' % e}
        finally:
            try:
                im.logout()
            except Exception:
                pass
    if geaendert:
        # Frisch nachladen und nur das eigene Feld mischen: der Abgleich dauert, und `data` ist von
        # vorher -- inzwischen angelegte Postfaecher oder Einstellungen gingen sonst verloren.
        frisch = mail_data()
        if frisch:
            frisch.setdefault('auto_log', {}).update(log)
            mail_save(frisch)
    MAIL_POLL.update(ts=jetzt, letzte=out)
    return out

def _auto_reply(acc, p, an, betreff, msgid):
    msg = MIMEText(p['auto_text'], 'plain', 'utf-8')
    msg['From'] = acc['email']
    msg['To'] = an
    msg['Subject'] = p['auto_betreff'] or 'Automatische Antwort'
    msg['Auto-Submitted'] = 'auto-replied'          # verhindert Schleifen mit anderen Autorespondern
    msg['X-Auto-Response-Suppress'] = 'All'
    if msgid:
        msg['In-Reply-To'] = msgid
        msg['References'] = msgid
    sm = _connect_smtp(acc['smtp_host'], acc['smtp_port'], acc.get('smtp_mode', 'starttls'))
    try:
        sm.login(acc['email'], mail_password(acc))
        sm.sendmail(acc['email'], [an], msg.as_string())
    finally:
        try:
            sm.quit()
        except Exception:
            pass

def api_mail_refresh(d):
    """Abgleich = alle Ordner abonnieren + neue Nachrichten holen (Autoresponder laeuft mit)."""
    if not mail_check(d.get('token')):
        return {'error': 'gesperrt', 'auth': True}
    if MAIL_POLL['laeuft']:
        return {'ok': True, 'laeuft': True}
    MAIL_POLL['laeuft'] = True
    abos = 0
    try:
        data = mail_data() or {}
        for a in data.get('accounts', []):
            try:
                im = _imap_login(a)
                try:
                    abos += _alle_abonnieren(im)
                finally:
                    im.logout()
            except Exception:
                pass
        return {'ok': True, 'stand': mail_poll_einmal(), 'ts': MAIL_POLL['ts'], 'abonniert': abos}
    finally:
        MAIL_POLL['laeuft'] = False

def mail_poll_loop():
    """Automatischer Abgleich. Intervall = kleinstes poll_stunden aller Postfaecher (Standard 24 h)."""
    while True:
        try:
            data = mail_data()
            if data and data.get('accounts'):
                std = min(_prefs(data, a['id'])['poll_stunden'] for a in data['accounts'])
                if time.time() - MAIL_POLL['ts'] >= std * 3600 and not MAIL_POLL['laeuft']:
                    MAIL_POLL['laeuft'] = True
                    try:
                        mail_poll_einmal()
                    finally:
                        MAIL_POLL['laeuft'] = False
        except Exception:
            pass
        time.sleep(600)

def api_mail_messages(token, account_id, folder, offset=0, limit=30):
    if not mail_check(token):
        return {'error': 'gesperrt', 'auth': True}
    im, acc = _imap(account_id)
    try:
        typ, _sel = im.select(_mbox(folder), readonly=True)
        if typ != 'OK':
            return {'error': 'Ordner nicht gefunden'}
        typ, data = im.uid('search', None, 'ALL')
        uids = list(reversed(data[0].split())) if data and data[0] else []
        out = []
        for uid in uids[offset:offset + limit]:
            typ, d = im.uid('fetch', uid, '(FLAGS BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])')
            if typ != 'OK' or not d or not isinstance(d[0], tuple):
                continue
            flags = re.findall(r'\\(\w+)', d[0][0].decode('utf-8', 'replace'))
            msg = email_lib.message_from_bytes(d[0][1])
            try:
                date_iso = email.utils.parsedate_to_datetime(msg.get('Date', '')).isoformat()
            except Exception:
                date_iso = ''
            out.append({'uid': uid.decode(), 'from': _decode_hdr(msg.get('From', '')),
                        'subject': _decode_hdr(msg.get('Subject', '')) or '(kein Betreff)',
                        'date': date_iso, 'seen': 'Seen' in flags, 'flagged': 'Flagged' in flags})
        return {'messages': out, 'total': len(uids)}
    finally:
        im.logout()

def _dateiname(part):
    """part.get_filename() sicher: Ein RFC-2231-Dateiname mit Zeichensatz 'undefined'/'idna'
    (filename*=undefined''...) wirft UnicodeError in email.utils.collapse_rfc2231_value, das
    nur LookupError faengt -- sonst kippt das Oeffnen der Nachricht bzw. der Anhang-Download.
    Rueckgabe False (statt None) im Fehlerfall: ein Name WAR angegeben, nur nicht decodierbar --
    das braucht _mail_parts, um einen Ersatznamen nur bei einem kaputten, nicht bei einem schlicht
    fehlenden Namen zu vergeben (None bleibt 'kein Dateiname angegeben')."""
    try:
        return part.get_filename()
    except (LookupError, ValueError):
        return False

def _content_charset(part):
    """part.get_content_charset() sicher: Bei der RFC-2231-Form (charset*=...) wirft ein NUL-Byte im
    Zeichensatznamen schon HIER ein ValueError ('embedded null character'), bevor _dek() ueberhaupt
    laeuft -- gleiches Muster wie _dateiname()."""
    try:
        return part.get_content_charset()
    except (LookupError, ValueError):
        return None

def _mail_parse(raw):
    """email.message_from_bytes() sicher: Ein praeparierter Kopf wie 'boundary*=undefined''X' wirft
    schon beim Parsen UnicodeError (gleiche Ursache wie bei _dateiname/_content_charset, hier trifft
    es aber schon den Aufbau der Message) -- eine einzelne so kaputte Mail darf die Nachrichtenliste
    bzw. deren Ansicht nicht kippen, sie gilt dann als nicht lesbar (None)."""
    try:
        return email_lib.message_from_bytes(raw)
    except (LookupError, ValueError):
        return None

def _mail_parts(msg):
    """Text/HTML-Body + Anhangsliste (idx = Position im MIME-Walk, fuer spaeteren Attachment-Abruf)."""
    text_body, html_body, attachments = '', '', []
    for idx, part in enumerate(msg.walk()):
        if part.is_multipart():
            continue
        cdisp = str(part.get('Content-Disposition') or '')
        ctype = part.get_content_type()
        roh_fn = _dateiname(part)
        fn = _decode_hdr(roh_fn) if roh_fn else ''
        ist_anhangstyp = ctype not in ('text/plain', 'text/html')
        # 'inline' zaehlt wie 'attachment' mit, aber nur wenn ein Dateiname angegeben war und sich
        # nicht decodieren liess (roh_fn is False) -- sonst wuerde jeder namenlose inline-Teil (z.B.
        # ein cid-Bild ohne Namen) faelschlich als Anhang auftauchen, statt unsichtbar zu bleiben.
        if 'attachment' in cdisp or (ist_anhangstyp and (fn or roh_fn is False)):
            attachments.append({'idx': idx, 'filename': fn or ('anhang-%d' % idx),
                                'size': len(part.get_payload(decode=True) or b''), 'type': ctype})
        elif ctype == 'text/plain' and not text_body:
            text_body = _dek(part.get_payload(decode=True) or b'', _content_charset(part))
        elif ctype == 'text/html' and not html_body:
            html_body = _dek(part.get_payload(decode=True) or b'', _content_charset(part))
    return text_body, html_body, attachments

def api_mail_message(token, account_id, folder, uid):
    if not mail_check(token):
        return {'error': 'gesperrt', 'auth': True}
    im, acc = _imap(account_id)
    try:
        im.select(_mbox(folder))
        typ, d = im.uid('fetch', uid.encode(), '(RFC822)')
        if typ != 'OK' or not d or not isinstance(d[0], tuple):
            return {'error': 'Nachricht nicht gefunden'}
        msg = _mail_parse(d[0][1])
        if msg is None:
            return {'error': 'Nachricht nicht lesbar'}
        im.uid('store', uid.encode(), '+FLAGS', '(\\Seen)')
        text_body, html_body, attachments = _mail_parts(msg)
        return {'from': _decode_hdr(msg.get('From', '')), 'to': _decode_hdr(msg.get('To', '')),
                'cc': _decode_hdr(msg.get('Cc', '')), 'subject': _decode_hdr(msg.get('Subject', '')),
                'date': msg.get('Date', ''), 'messageId': msg.get('Message-ID', ''),
                'text': text_body, 'html': html_body, 'attachments': attachments}
    finally:
        im.logout()

def mail_attachment_bytes(token, account_id, folder, uid, idx):
    if not mail_check(token):
        return None, None, None
    im, acc = _imap(account_id)
    try:
        im.select(_mbox(folder), readonly=True)
        typ, d = im.uid('fetch', uid.encode(), '(RFC822)')
        if typ != 'OK' or not d or not isinstance(d[0], tuple):
            return None, None, None
        msg = _mail_parse(d[0][1])
        if msg is None:
            return None, None, None
        for i, part in enumerate(msg.walk()):
            if i == idx and not part.is_multipart():
                payload = part.get_payload(decode=True) or b''
                roh_fn = _dateiname(part)
                fn = _decode_hdr(roh_fn) if roh_fn else 'anhang'
                return payload, part.get_content_type(), fn
        return None, None, None
    finally:
        im.logout()

def api_mail_flag(d):
    if not mail_check(d.get('token')):
        return {'error': 'gesperrt', 'auth': True}
    im, acc = _imap(d.get('account'))
    try:
        im.select(_mbox(d['folder']))
        op = '+FLAGS' if d.get('on', True) else '-FLAGS'
        im.uid('store', d['uid'].encode(), op, '(\\%s)' % d.get('flag', 'Seen'))
        return {'ok': True}
    finally:
        im.logout()

def _uid_loeschen(im, uid):
    """Nur DIESE Nachricht endgueltig entfernen: UID EXPUNGE (UIDPLUS). Ein blankes EXPUNGE naehme
    jede andere \\Deleted-Mail im Ordner mit (etwa von einem zweiten Client nur markierte);
    ohne UIDPLUS bleibt es deshalb beim Markieren."""
    im.uid('store', uid, '+FLAGS', '(\\Deleted)')
    typ, cap = im.capability()
    if typ == 'OK' and b'UIDPLUS' in b' '.join(c for c in cap if c).upper().split():
        im.uid('expunge', uid)

def api_mail_delete(d):
    if not mail_check(d.get('token')):
        return {'error': 'gesperrt', 'auth': True}
    im, acc = _imap(d.get('account'))
    try:
        im.select(_mbox(d['folder']))
        _uid_loeschen(im, d['uid'].encode())
        return {'ok': True}
    finally:
        im.logout()

def api_mail_move(d):
    if not mail_check(d.get('token')):
        return {'error': 'gesperrt', 'auth': True}
    im, acc = _imap(d.get('account'))
    try:
        im.select(_mbox(d['folder']))
        typ, _r = im.uid('copy', d['uid'].encode(), _mbox(d['to']))
        if typ != 'OK':
            return {'error': 'Verschieben fehlgeschlagen'}
        _uid_loeschen(im, d['uid'].encode())
        return {'ok': True}
    finally:
        im.logout()

def api_mail_send(d):
    if not mail_check(d.get('token')):
        return {'error': 'gesperrt', 'auth': True}
    acc = mail_account_by_id(mail_data(), d.get('account'))
    if not acc:
        return {'error': 'Postfach nicht gefunden'}
    to, cc, bcc = d.get('to', ''), d.get('cc', ''), d.get('bcc', '')
    if not to.strip():
        return {'error': 'Empfänger fehlt'}
    msg = MIMEMultipart()
    msg['From'] = acc['email']; msg['To'] = to
    if cc: msg['Cc'] = cc
    msg['Subject'] = d.get('subject', '')
    msg['Date'] = email.utils.formatdate(localtime=True)
    msg['Message-ID'] = email.utils.make_msgid()
    if d.get('inReplyTo'): msg['In-Reply-To'] = d['inReplyTo']
    if d.get('references'): msg['References'] = d['references']
    msg.attach(MIMEText(d.get('text', ''), 'plain', 'utf-8'))
    for att in d.get('attachments') or []:
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(base64.b64decode(att['contentBase64']))
        email_encoders.encode_base64(part)
        part.add_header('Content-Disposition', 'attachment', filename=att.get('filename', 'anhang'))
        msg.attach(part)
    rcpt = [a.strip() for a in (to + ',' + cc + ',' + bcc).split(',') if a.strip()]
    try:
        sm = _connect_smtp(acc['smtp_host'], acc['smtp_port'], acc.get('smtp_mode', 'starttls'))
        sm.login(acc['email'], mail_password(acc))
        sm.sendmail(acc['email'], rcpt, msg.as_string()); sm.quit()
    except Exception as e:
        return {'error': 'Senden fehlgeschlagen: %s' % e}
    try:  # Ablage im Gesendet-Ordner ist best effort -- Senden selbst ist bereits erfolgreich
        im = _imap_login(acc)
        typ, data = im.list()
        sent_raw = 'Sent'
        for line in data:
            s = line.decode('utf-8', 'replace') if isinstance(line, bytes) else line
            if '\\Sent' in s:
                m = re.search(r'"([^"]+)"\s*$', s)
                if m: sent_raw = m.group(1)
        im.append('"%s"' % sent_raw.replace('"', '\\"'), '\\Seen',
                  imaplib.Time2Internaldate(time.time()), msg.as_bytes())
        im.logout()
    except Exception:
        pass
    return {'ok': True}

# ---------- OPNsense (Command-Center-Karte) ----------
# Ueber die REST-API mit API-Key/Secret, NICHT ueber die Weboberflaeche: OPNsense sendet
# `X-Frame-Options: SAMEORIGIN`, ein iframe bliebe leer. Mit einem API-Key entfaellt ausserdem
# Passwort und 2FA. Key + Secret liegen DPAPI-verschluesselt in derselben Sperrzone wie die Mail-Daten.
OPN_FILE = os.path.join(MAIL_DIR, 'opnsense.json')

def opn_data():
    if not os.path.isfile(OPN_FILE):
        return None
    try:   # fail-closed: sonst ueberschriebe api_opnsense_setup eine nur gerade unlesbare Datei
        d = json.load(open(OPN_FILE, encoding='utf-8'))
    except Exception as e:
        raise RuntimeError('opnsense.json unlesbar (%s) -- nichts gespeichert' % e.__class__.__name__)
    if not isinstance(d, dict):
        raise RuntimeError('opnsense.json unlesbar (kein Objekt) -- nichts gespeichert')
    return d

def api_opnsense_status():
    d = opn_data()
    return {'configured': bool(d), 'url': (d or {}).get('url', ''),
            'pruefen_ssl': bool((d or {}).get('pruefen_ssl', True))}

def api_opnsense_setup(d):
    url = (d.get('url') or '').strip().rstrip('/')
    key = (d.get('key') or '').strip()
    secret = (d.get('secret') or '').strip()
    if not url.startswith(('http://', 'https://')):
        return {'error': 'Adresse muss mit https:// beginnen'}
    alt = opn_data() or {}
    # Gespeicherte Zugangsdaten nur an die gespeicherte URL -- sonst liessen sie sich an jeden Server umleiten
    if not (key and secret) and alt.get('key_enc') and url != alt.get('url'):
        return {'error': 'Neue Adresse — Zugangsdaten neu eingeben'}
    if not key and alt.get('key_enc'):
        key = dpapi_unprotect(base64.b64decode(alt['key_enc'])).decode('utf-8')
    if not secret and alt.get('secret_enc'):
        secret = dpapi_unprotect(base64.b64decode(alt['secret_enc'])).decode('utf-8')
    if not (key and secret):
        return {'error': 'API-Key und Secret fehlen'}
    pruefen_ssl = bool(d.get('pruefen_ssl', True))
    probe = _opn_get(url, key, secret, '/api/core/firmware/status', pruefen_ssl)
    if probe.get('error'):
        return {'error': 'Verbindung fehlgeschlagen: %s' % probe['error']}
    os.makedirs(MAIL_DIR, exist_ok=True)
    write_file(OPN_FILE, json.dumps({
        'url': url, 'pruefen_ssl': pruefen_ssl,
        'key_enc': base64.b64encode(dpapi_protect(key.encode('utf-8'))).decode('ascii'),
        'secret_enc': base64.b64encode(dpapi_protect(secret.encode('utf-8'))).decode('ascii')}, indent=1))
    return {'ok': True}

def api_opnsense_remove(d):
    if os.path.isfile(OPN_FILE):
        os.remove(OPN_FILE)
    return {'ok': True}

def _opn_get(url, key, secret, pfad, pruefen_ssl=True, timeout=8):
    """Ein GET gegen die OPNsense-API. Basic-Auth mit Key als Benutzer, Secret als Passwort."""
    import ssl
    ziel = url.rstrip('/') + pfad
    req = urllib.request.Request(ziel, headers={
        'Authorization': 'Basic ' + base64.b64encode(('%s:%s' % (key, secret)).encode()).decode(),
        'Accept': 'application/json', 'User-Agent': 'puox-os'})
    ctx = None
    if not pruefen_ssl:
        # Selbstsigniertes Zertifikat im eigenen Netz -- bewusste Entscheidung des Nutzers,
        # deshalb ein eigener Schalter statt einer stillen Ausnahme.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return json.loads(r.read(400000).decode('utf-8', 'replace'))
    except urllib.error.HTTPError as e:
        return {'error': 'HTTP %s (Key/Secret pruefen)' % e.code}
    except Exception as e:
        return {'error': '%s' % e}

OPN_CACHE = {'ts': 0, 'daten': None}

def api_opnsense():
    """Sammelt Firmware, Systemlast, Schnittstellen und aktive VPN-Sitzungen. 30 s gecacht --
    die Karte fragt beim Oeffnen und dann regelmaessig, das soll die Firewall nicht belasten."""
    d = opn_data()
    if not d:
        return {'configured': False}
    if time.time() - OPN_CACHE['ts'] < 30 and OPN_CACHE['daten']:
        return OPN_CACHE['daten']
    key = dpapi_unprotect(base64.b64decode(d['key_enc'])).decode('utf-8')
    secret = dpapi_unprotect(base64.b64decode(d['secret_enc'])).decode('utf-8')
    hol = lambda p: _opn_get(d['url'], key, secret, p, d.get('pruefen_ssl', True))
    fw = hol('/api/core/firmware/status')
    if fw.get('error'):
        return {'configured': True, 'error': fw['error']}
    akt = hol('/api/diagnostics/activity/getActivity')
    ifs = hol('/api/diagnostics/interface/getInterfaceNames')
    wg = hol('/api/wireguard/service/show')
    raus = {'configured': True,
            'firmware': {'version': fw.get('product_version') or fw.get('product', {}).get('product_version', ''),
                         'aktualisierungen': fw.get('status') or '',
                         'name': fw.get('product_name') or fw.get('product', {}).get('product_name', 'OPNsense')},
            'last': (akt.get('headers') or [None, None, None])[2] if isinstance(akt.get('headers'), list) else '',
            'schnittstellen': ifs if isinstance(ifs, dict) and not ifs.get('error') else {},
            'vpn': []}
    zeilen = (wg.get('rows') if isinstance(wg, dict) else None) or []
    for z in zeilen:
        if isinstance(z, dict) and z.get('type') == 'peer':
            raus['vpn'].append({'name': z.get('name', '?'), 'if': z.get('if', ''),
                                'letzte': z.get('latest-handshake', ''),
                                'rein': z.get('transfer-rx', ''), 'raus': z.get('transfer-tx', '')})
    OPN_CACHE.update(ts=time.time(), daten=raus)
    return raus

# ---------- Zugangsschutz (gilt fuer JEDE Anfrage, auch von localhost) ----------
# Der Server liest und schreibt den ganzen Vault und startet `claude -p`. Sobald er nicht mehr nur
# auf 127.0.0.1 horcht, ist das ohne Anmeldung ein offener Zugang zu personenbezogenen Kundendaten
# (DSGVO Art. 32). Darum: Subnetz-Grenze UND PIN.
#
# Grenze: Das laeuft per HTTPS mit selbstsigniertem Zertifikat; die PIN geht
# verschluesselt ueber das Netz, Port 80 leitet nur auf https weiter. Kein Geraet kennt das Zertifikat
# von selbst -- ohne Import zeigt der Browser eine Warnung.
ZUGANG_FILE = os.path.join(MAIL_DIR, 'zugang.json')
ZUGANG_SESSIONS = {}                 # token -> Ablauf-Zeitstempel
ZUGANG_TTL = 30 * 86400              # 30 Tage, damit man nicht taeglich neu tippt
ZUGANG_VERSUCHE = {}                 # IP -> (Anzahl, Sperre-bis)
ZUGANG_MAX = 8                       # danach 15 Minuten Pause fuer diese IP
ZUGANG_PAUSE = 900
# Ohne Anmeldung erreichbar: was die Anmeldeseite zum Anzeigen braucht. `/` und `/login` stehen
# bewusst NICHT hier -- Unangemeldete bekommen dort ueber zugang_abweisen() die Anmeldeseite,
# Angemeldete index.html.
ZUGANG_FREI = {'/api/zugang/status', '/api/zugang/anmelden', '/api/zugang/einrichten', '/logo.svg'}

def zugang_data():
    if not os.path.isfile(ZUGANG_FILE):
        return None
    # Fail-closed: eine vorhandene, aber kaputte Datei ist KEIN "noch nicht eingerichtet" --
    # sonst setzte jeder im Netz ueber /api/zugang/einrichten eine neue PIN.
    try:
        d = json.load(open(ZUGANG_FILE, encoding='utf-8'))
        if d.get('hash') and d.get('salt'):
            return d
    except Exception:
        pass
    raise RuntimeError('zugang.json unlesbar -- Anmeldung gesperrt. Datei pruefen oder loeschen (dann neu einrichten)')

def zugang_eingerichtet():
    return os.path.isfile(ZUGANG_FILE)   # bewusst nur "Datei da" -- Inhalt prueft zugang_data()

_VERSUCHE_LOCK = threading.Lock()

def pin_bremse(schluessel):
    """Zaehlt den Versuch VOR der langsamen PIN-Pruefung und unter Lock -- sonst saehen parallele
    Anfragen alle denselben Zaehlerstand und die Bremse liefe ins Leere. None = darf pruefen."""
    with _VERSUCHE_LOCK:
        n, sperre = ZUGANG_VERSUCHE.get(schluessel, (0, 0))
        if sperre > time.time():
            return 'Zu viele Fehlversuche — in %d Minuten erneut versuchen' % max(1, int((sperre - time.time()) / 60))
        if sperre:   # eine fruehere Sperre ist gerade abgelaufen -- neues Fenster, sonst sperrt
            n = 0    # der naechste einzelne Fehlversuch (oder die naechste Tipp-Pause) sofort wieder
        n += 1
        ZUGANG_VERSUCHE[schluessel] = (n, time.time() + ZUGANG_PAUSE if n >= ZUGANG_MAX else 0)
    return None

def api_zugang_status():
    return {'eingerichtet': zugang_eingerichtet()}

def api_zugang_einrichten(d):
    """Nur solange noch keine PIN gesetzt ist -- danach fuehrt der Weg ueber /api/zugang/aendern."""
    if zugang_eingerichtet():
        return {'error': 'Zugangs-PIN ist bereits eingerichtet'}
    pin = d.get('pin') or ''
    if not PIN_RE.match(pin):
        return {'error': 'PIN: 4 bis 32 Zeichen (Ziffern und Buchstaben)'}
    salt = secrets.token_bytes(16)
    os.makedirs(MAIL_DIR, exist_ok=True)
    write_file(ZUGANG_FILE, json.dumps({'salt': base64.b64encode(salt).decode('ascii'),
                                        'hash': _pin_hash(pin, salt), 'seit': time.strftime('%Y-%m-%d')}, indent=1))
    return {'ok': True, 'token': zugang_neuer_token()}

def api_zugang_aendern(d, ip='?'):
    if not zugang_pruefe(d.get('token')):
        return {'error': 'nicht angemeldet'}
    dd = zugang_data() or {}
    alt = d.get('alt') or ''
    bremse = pin_bremse(ip)       # derselbe Zaehler wie die Anmeldung: es ist dieselbe PIN
    if bremse:
        return {'error': bremse}
    if _pin_hash(alt, base64.b64decode(dd['salt'])) != dd['hash']:
        return {'error': 'Bisherige PIN stimmt nicht'}
    ZUGANG_VERSUCHE.pop(ip, None)
    neu = d.get('neu') or ''
    if not PIN_RE.match(neu):
        return {'error': 'Neue PIN: 4 bis 32 Zeichen'}
    salt = secrets.token_bytes(16)
    write_file(ZUGANG_FILE, json.dumps({'salt': base64.b64encode(salt).decode('ascii'),
                                        'hash': _pin_hash(neu, salt), 'seit': time.strftime('%Y-%m-%d')}, indent=1))
    ZUGANG_SESSIONS.clear()          # alle Geraete muessen sich neu anmelden
    sessions_sichern()
    return {'ok': True, 'token': zugang_neuer_token()}

# Sitzungen ueberdauern einen Neustart -- sonst waere die 30-Tage-Zusage wertlos, weil jeder
# Start von start.bat alle Geraete aussperrt. Auf Platte liegt NUR der SHA256 des Tokens:
# wer die Datei liest, kann sich damit nicht anmelden.
SESSION_FILE = os.path.join(MAIL_DIR, 'sitzungen.json')
_SESSION_LOCK = threading.Lock()

def _tok_hash(tok):
    return hashlib.sha256(('puox-os:' + tok).encode('utf-8')).hexdigest()

def sessions_laden():
    if not os.path.isfile(SESSION_FILE):
        return
    try:
        d = json.load(open(SESSION_FILE, encoding='utf-8'))
    except Exception:
        return
    jetzt = time.time()
    for h, exp in (d.get('sitzungen') or {}).items():
        if exp > jetzt:
            ZUGANG_SESSIONS[h] = exp

def sessions_sichern():
    with _SESSION_LOCK:
        jetzt = time.time()
        # list(...): andere Threads legen ohne dieses Lock Sitzungen an ("dict changed size"). Abgelaufene
        # einzeln entfernen statt clear()+update() -- dazwischen angelegte Sitzungen gingen sonst verloren.
        for h, e in list(ZUGANG_SESSIONS.items()):
            if e <= jetzt:
                ZUGANG_SESSIONS.pop(h, None)
        aktiv = dict(list(ZUGANG_SESSIONS.items()))
        try:
            os.makedirs(MAIL_DIR, exist_ok=True)
            write_file(SESSION_FILE, json.dumps({'sitzungen': aktiv}, indent=1))
        except OSError:
            pass                      # Sitzung gilt dann nur bis zum naechsten Neustart

def zugang_neuer_token():
    tok = secrets.token_urlsafe(32)
    ZUGANG_SESSIONS[_tok_hash(tok)] = time.time() + ZUGANG_TTL
    sessions_sichern()
    return tok

def zugang_pruefe(token):
    if not token:
        return False
    h = _tok_hash(token)
    exp = ZUGANG_SESSIONS.get(h)
    if not exp or exp < time.time():
        return False
    # Gleitendes Ablaufdatum; nur gelegentlich auf Platte schreiben, nicht bei jeder Anfrage
    if exp - time.time() < ZUGANG_TTL - 3600:
        ZUGANG_SESSIONS[h] = time.time() + ZUGANG_TTL
        sessions_sichern()
    return True

def zugang_abmelden(token):
    if token:
        ZUGANG_SESSIONS.pop(_tok_hash(token), None)
        sessions_sichern()

def api_zugang_anmelden(d, ip='?'):
    """Zaehlt Fehlversuche je IP -- ohne Bremse waere eine kurze PIN in Minuten durchprobiert."""
    dd = zugang_data()
    if not dd:
        return {'error': 'Noch keine Zugangs-PIN eingerichtet'}
    bremse = pin_bremse(ip)
    if bremse:
        return {'error': bremse}
    pin = d.get('pin') or ''
    if _pin_hash(pin, base64.b64decode(dd['salt'])) != dd['hash']:
        return {'error': 'PIN stimmt nicht'}
    ZUGANG_VERSUCHE.pop(ip, None)
    return {'ok': True, 'token': zugang_neuer_token()}

# Wer ueberhaupt anklopfen darf -- die zweite Grenze neben der PIN. Gepflegt in netzzugang.json:
#   modus: "lan"       -> localhost + eigenes /24 (Standard)
#          "vpn"       -> localhost + NUR die unten eingetragenen Netze/Adressen (z. B. das VPN)
#          "liste"     -> NUR die eingetragenen Netze/Adressen, localhost ebenfalls nur wenn gelistet
#   erlaubt: Liste aus Einzel-IPs ("10.8.0.5") und CIDR-Bereichen ("10.8.0.0/24")
NETZ_FILE = os.path.join(BASE, 'netzzugang.json')
NETZ_STANDARD = {'modus': 'lan', 'erlaubt': [], 'hinweis':
                 'modus: lan | vpn | liste. Bei vpn/liste zaehlt ausschliesslich "erlaubt" '
                 '(Einzel-IP oder CIDR wie 10.8.0.0/24). Aenderung wirkt sofort, kein Neustart noetig.'}
_NETZ_CFG = {'ts': 0, 'daten': None}

def netz_cfg():
    """60 s gecacht, damit eine Aenderung ohne Neustart greift, ohne bei jeder Anfrage zu lesen."""
    if time.time() - _NETZ_CFG['ts'] < 60 and _NETZ_CFG['daten'] is not None:
        return _NETZ_CFG['daten']
    d = dict(NETZ_STANDARD)
    if os.path.isfile(NETZ_FILE):
        try:
            gespeichert = json.load(open(NETZ_FILE, encoding='utf-8'))
            if gespeichert.get('modus') in ('lan', 'vpn', 'liste'):
                d['modus'] = gespeichert['modus']
            if isinstance(gespeichert.get('erlaubt'), list):
                d['erlaubt'] = [str(x).strip() for x in gespeichert['erlaubt'] if str(x).strip()]
        except Exception:
            pass
    else:
        try:
            write_file(NETZ_FILE, json.dumps(NETZ_STANDARD, indent=1, ensure_ascii=False))
        except Exception:
            pass
    _NETZ_CFG.update(ts=time.time(), daten=d)
    return d

def _ip_zu_zahl(ip):
    try:
        teile = [int(x) for x in ip.split('.')]
        if len(teile) != 4 or any(not 0 <= t <= 255 for t in teile):
            return None
        return (teile[0] << 24) | (teile[1] << 16) | (teile[2] << 8) | teile[3]
    except (ValueError, AttributeError):
        return None

def ip_passt(ip, eintrag):
    """Einzel-IP ('10.0.0.5') oder CIDR ('10.0.0.0/24'). Ungueltige Eintraege gelten nie."""
    if '/' not in eintrag:
        return ip == eintrag
    netz, _, bits = eintrag.partition('/')
    a, b = _ip_zu_zahl(ip), _ip_zu_zahl(netz)
    try:
        n = int(bits)
    except ValueError:
        return False
    if a is None or b is None or not 0 <= n <= 32:
        return False
    maske = 0 if n == 0 else ((1 << 32) - 1) ^ ((1 << (32 - n)) - 1)
    return (a & maske) == (b & maske)

def ip_im_eigenen_netz(ip):
    """Zweite Grenze neben der PIN. Was durchkommt, entscheidet netzzugang.json."""
    cfg = netz_cfg()
    modus, erlaubt = cfg['modus'], cfg['erlaubt']
    if any(ip_passt(ip, e) for e in erlaubt):
        return True
    if modus == 'liste':
        return False                      # wirklich nur die Liste, auch localhost muss drinstehen
    if ip in ('127.0.0.1', '::1'):
        return True                       # der Rechner selbst bleibt bei lan und vpn erreichbar
    if modus == 'vpn':
        return False                      # sonst ausschliesslich die eingetragenen Netze
    return any(ip.rsplit('.', 1)[0] == e.rsplit('.', 1)[0] for e in NETZ_EIGENE())

_NETZ = {'ts': 0, 'ips': []}

def NETZ_EIGENE():
    """Eigene IPv4-Adressen, 60 s gecacht (DHCP kann sie wechseln)."""
    if time.time() - _NETZ['ts'] < 60 and _NETZ['ips']:
        return _NETZ['ips']
    import socket
    ips = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            a = info[4][0]
            if not a.startswith('127.'):
                ips.append(a)
    except Exception:
        pass
    _NETZ.update(ts=time.time(), ips=ips)
    return ips

def login_seite(einrichten=False):
    """Eigenstaendige Seite -- index.html wird erst nach der Anmeldung ausgeliefert, damit ein
    Unangemeldeter nicht einmal die Oberflaeche und ihre Endpunkte zu sehen bekommt.
    Die PIN-Eingabe zeigt nichts an (auch keine Punkte), wie im Mail-Tab."""
    titel = 'Zugang einrichten' if einrichten else 'PUOX OS'
    knopf = 'Einrichten' if einrichten else 'Entsperren'
    hinweis = ('Beim ersten Start eine Zugangs-PIN festlegen: 4 bis 32 Zeichen, Ziffern und Buchstaben. '
               'Sie schützt den gesamten Zugriff auf die Wissensdatenbank — auch auf diesem Rechner.'
               if einrichten else 'Zugangs-PIN eingeben.')
    ziel = '/api/zugang/einrichten' if einrichten else '/api/zugang/anmelden'
    return """<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>%s</title><style>
:root{--bg:#131311;--panel:#1b1b18;--line:#2b2b26;--mint:#21F1A8;--cream:#E9E3D5;--dim:#8f8f83;color-scheme:dark}
*{box-sizing:border-box;margin:0}
body{height:100vh;display:flex;align-items:center;justify-content:center;background:
 radial-gradient(ellipse 130%% 82%% at 50%% 106%%,rgba(233,227,213,.10) 0%%,rgba(233,227,213,.042) 32%%,transparent 63%%),var(--bg);
 color:var(--cream);font:14px/1.5 system-ui,Segoe UI,sans-serif;padding:20px}
.box{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:28px 30px;
 width:min(390px,94vw);text-align:center}
h1{font-size:19px;letter-spacing:.18em;font-weight:700;margin-bottom:6px}
p{color:var(--dim);font-size:11.5px;line-height:1.6;margin-bottom:16px}
input{width:100%%;background:var(--bg);border:1px solid var(--line);border-radius:4px;color:var(--cream);
 padding:11px 12px;font:15px system-ui;text-align:center;caret-color:transparent}
input:focus{outline:none;border-color:var(--mint)}
input.tippt{animation:p .28s ease}
@keyframes p{0%%{border-color:var(--mint);box-shadow:0 0 0 2px rgba(33,241,168,.16)}100%%{border-color:var(--line);box-shadow:none}}
button{margin-top:12px;width:100%%;background:none;border:1px solid var(--mint);color:var(--mint);
 border-radius:4px;padding:10px;cursor:pointer;font:inherit;font-weight:600}
button:hover{background:var(--mint);color:var(--bg)}
small{display:block;margin-top:10px;color:#FF6B6B;font-size:11.5px;min-height:16px}
</style></head><body><div class="box">
<h1>%s</h1><p>%s</p>
<input id="p" placeholder="PIN eingeben" autocomplete="off" spellcheck="false" autofocus>
<button id="b">%s</button><small id="m"></small>
</div><script>
/* Die Eingabe bleibt unsichtbar: der Wert lebt in einer Closure, das Feld ist immer leer. */
var pin='',p=document.getElementById('p'),b=document.getElementById('b'),m=document.getElementById('m');
var EINRICHTEN=%s;
function puls(){p.classList.remove('tippt');void p.offsetWidth;p.classList.add('tippt');}
p.addEventListener('keydown',function(e){
  if(e.key==='Enter'){los(true);return;}
  if(e.key==='Tab')return;
  e.preventDefault();
  if(e.key==='Backspace')pin=pin.slice(0,-1);
  else if(e.key==='Delete'||e.key==='Escape')pin='';
  else if(e.key.length===1)pin=(pin+e.key).slice(0,32);
  else return;
  p.value='';puls();bald();});
p.addEventListener('paste',function(e){e.preventDefault();
  var t=(e.clipboardData||window.clipboardData).getData('text')||'';
  pin=(pin+t.replace(/\\s/g,'')).slice(0,32);p.value='';puls();bald();});
p.addEventListener('input',function(){if(p.value){pin=(pin+p.value).replace(/\\s/g,'').slice(0,32);p.value='';puls();bald();}});
/* Stille Pruefung nach 600 ms ohne Tastendruck: stimmt die PIN, ist man
   sofort drin -- ohne "Entsperren". Nicht mehr bei jedem Anschlag: jeder Zwischenstand zaehlte sonst
   als Fehlversuch gegen die PIN-Bremse. Beim ERSTEN Einrichten nicht, dort waere jede Zwischeneingabe
   schon die endgueltige PIN. `laeuft`/`zuletzt` verhindern, dass dieselbe Eingabe mehrfach laeuft. */
var laeuft=false,zuletzt='',warte=0;
function bald(){clearTimeout(warte);warte=setTimeout(probe,600);}
function probe(){
  if(EINRICHTEN||laeuft||pin===zuletzt||pin.length<4)return;
  laeuft=true;zuletzt=pin;
  var versuch=pin;
  fetch('%s',{method:'POST',body:JSON.stringify({pin:versuch})}).then(function(r){return r.json();})
   .then(function(r){laeuft=false;if(r.ok)location.href='/';})
   .catch(function(){laeuft=false;});}
function los(mitMeldung){
  if(pin.length<4){if(mitMeldung)m.textContent='PIN: mindestens 4 Zeichen';return;}
  b.disabled=true;m.textContent='';
  zuletzt=pin;
  fetch('%s',{method:'POST',body:JSON.stringify({pin:pin})}).then(function(r){return r.json();}).then(function(r){
    b.disabled=false;
    if(r.error){m.textContent=r.error;pin='';zuletzt='';return;}
    location.href='/';}).catch(function(e){b.disabled=false;m.textContent='Server nicht erreichbar';});}
b.onclick=function(){los(true);};p.focus();
</script></body></html>""" % (titel, titel, hinweis, knopf,
                              'true' if einrichten else 'false', ziel, ziel)

# ---------- HTTP ----------
GETS = {'/api/manifest': api_manifest, '/api/dbcheck': api_dbcheck, '/api/monitoring': api_monitoring,
        '/api/uptime': api_uptime, '/api/config': api_config, '/api/status': api_status,
        '/api/termine': api_termine, '/api/potenzielle': api_pot, '/api/mail/status': api_mail_status,
        '/api/kalender/status': api_kalender_status, '/api/theme': api_theme,
        '/api/abteilungen': api_abteilungen, '/api/zugang/status': api_zugang_status,
        '/api/graph': api_graph, '/api/opnsense': api_opnsense,
        '/api/opnsense/status': api_opnsense_status,
        '/api/schriften': api_schriften, '/api/explorer': api_explorer}
POSTS = {'/api/task/new': api_task_new, '/api/task/save': api_task_save, '/api/chat': api_chat_start,
         '/api/theme': api_theme_save,
         '/api/potenzielle': api_pot_new, '/api/kunde/new': api_kunde_new, '/api/dbupdate': api_dbupdate,
         '/api/termin/new': api_termin_new, '/api/termin/save': api_termin_save,
         '/api/termin/delete': api_termin_delete, '/api/git/commit': api_gitcommit,
         '/api/potenzielle/remove': api_pot_remove,
         '/api/kalender/setup': api_kalender_setup, '/api/kalender/remove': api_kalender_remove,
         '/api/kalender/toggle': api_kalender_toggle,
         '/api/hintergrund': api_hintergrund_save, '/api/hintergrund/remove': api_hintergrund_remove,
         '/api/schriften': api_schrift_save, '/api/schriften/remove': api_schrift_remove,
         '/api/opnsense/setup': api_opnsense_setup, '/api/opnsense/remove': api_opnsense_remove,
         '/api/mail/setup': api_mail_setup, '/api/mail/lock': api_mail_lock,
         '/api/mail/account/add': api_mail_account_add, '/api/mail/account/remove': api_mail_account_remove,
         '/api/mail/flag': api_mail_flag, '/api/mail/delete': api_mail_delete, '/api/mail/move': api_mail_move,
         '/api/mail/send': api_mail_send, '/api/mail/folder': api_mail_folder,
         '/api/mail/prefs': api_mail_prefs_save, '/api/mail/refresh': api_mail_refresh}

SCHREIB_STUECK = 65536  # Bytes je Rumpf-Schreibzugriff in out(): H.timeout gilt je Aufruf von
# wfile.write, nicht fuer die gesamte Uebertragung -- ein einziger Aufruf mit dem ganzen Rumpf
# liesse die Frist sonst fuer grosse Antworten an einen langsamen, aber staendig lesenden Client
# gelten (Hintergrundbild, Mail-Anhang, /api/file) und braeche sie nach 30 s mitten im Rumpf ab.

class H(BaseHTTPRequestHandler):
    # Eigener Server-Kopf: daran erkennt der Start, ob auf dem Port wirklich PUOX-OS
    # sitzt oder ein fremder Server (siehe auf_port()).
    server_version = 'PUOX-OS'
    timeout = 30   # Sekunden je Socket-Operation (auch TLS-Handshake): ein stummer Client belegt nur seinen Thread
    # ---- Zugangsschranke: laeuft vor JEDER Anfrage ----
    def klient_ip(self):
        return self.client_address[0] if self.client_address else '?'

    def token_aus_anfrage(self, q=None):
        """Erst Cookie (Browser schickt es von selbst mit), sonst ?token= aus der Anfrage."""
        keks = SimpleCookie(self.headers.get('Cookie') or '')
        if 'puox_zugang' in keks:
            return keks['puox_zugang'].value
        return (q or {}).get('token', [''])[0]

    def darf_durch(self, pfad, q=None):
        """(True, None) oder (False, Grund). Grund entscheidet ueber 403 vs. Anmeldeseite."""
        # Host-Zwang zuerst -- vor der IP-Pruefung und vor ZUGANG_FREI. Sonst waere
        # /login ueber jede beliebige Adresse erreichbar, die auf diesen Rechner zeigt,
        # und der Sinn der einen gueltigen Adresse dahin.
        if not host_ok(self.headers.get('Host')):
            return False, 'host'
        if not ip_im_eigenen_netz(self.klient_ip()):
            return False, 'netz'
        if pfad in ZUGANG_FREI:
            return True, None
        if not zugang_eingerichtet():
            return False, 'einrichten'
        return (True, None) if zugang_pruefe(self.token_aus_anfrage(q)) else (False, 'anmelden')

    def zugang_abweisen(self, grund, ist_seite):
        abweisung_merken(grund, self.klient_ip(), self.headers.get('Host'))
        if grund == 'host':
            # 421 Misdirected Request: "richtiger Server, falscher Name". Die gueltige
            # Adresse wird genannt -- sonst sucht man den Fehler beim Server, nicht am Namen.
            hinweis = 'Dieser Server wird ausschliesslich unter https://%s bedient.' % NAME
            if ist_seite:
                return self.out(('<!doctype html><meta charset="utf-8">'
                                 '<title>Falsche Adresse</title>'
                                 '<p>%s' % hinweis).encode('utf-8'), 'text/html', 421)
            return self.js({'error': hinweis, 'adresse': 'https://%s' % NAME}, 421)
        if grund == 'netz':
            return self.js({'error': 'Zugriff nur aus dem eigenen Netz'}, 403)
        if ist_seite:      # normale Seitenanfrage -> Anmeldeseite ausliefern
            return self.out(login_seite(grund == 'einrichten').encode('utf-8'), 'text/html', 401)
        return self.js({'error': 'nicht angemeldet', 'zugang': grund}, 401)

    def setze_zugang_keks(self, token):
        # HttpOnly: kein Auslesen per JavaScript. Secure: das Sitzungs-Token geht nur noch
        # ueber TLS -- seit der Umstellung auf https gibt es keinen Klartext-Pfad mehr.
        self.extra_headers = {'Set-Cookie':
            'puox_zugang=%s; Path=/; Max-Age=%d; HttpOnly; Secure; SameSite=Lax' % (token, ZUGANG_TTL)}

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        ok, grund = self.darf_durch(u.path, q)
        if not ok:
            return self.zugang_abweisen(grund, u.path == '/' or u.path == '/login')
        try:
            if u.path in ('/', '/login'):
                return self.out(open(os.path.join(BASE, 'index.html'), 'rb').read(), 'text/html')
            if u.path == '/logo.svg':
                # Fehlt die Datei, gibt es 404 statt 500: ein fehlendes Bild darf die
                # Anmeldeseite (ohne Anmeldung erreichbar) nicht mitreissen.
                p = os.path.join(BASE, 'logo.svg')
                if not os.path.exists(p):
                    return self.send_error(404)
                return self.out(open(p, 'rb').read(), 'image/svg+xml')
            if u.path.startswith('/schrift/'):
                p = schrift_datei(unquote(u.path[len('/schrift/'):]))   # "Puox%20Sans.woff2" -> Leerzeichen
                if not p:
                    return self.send_error(404)
                return self.out(open(p, 'rb').read(), SCHRIFT_MIME[os.path.splitext(p)[1].lower()])
            if u.path == '/hintergrund':
                p = _bg_datei()
                if not p:
                    return self.send_error(404)
                mime = next(m for m, e in BG_EXT.items() if p.endswith(e))
                return self.out(open(p, 'rb').read(), mime)
            if u.path == '/api/mail/autoconfig':
                return self.js(api_mail_autoconfig(q.get('email', [''])[0]))
            if u.path == '/api/termin/suche':
                return self.js(api_termin_suche(q.get('q', [''])[0]))
            if u.path == '/api/suche':
                return self.js(api_suche(q.get('q', [''])[0], q.get('typ', [''])[0],
                                         q.get('status', [''])[0], int(q.get('limit', ['60'])[0])))
            if u.path == '/api/file':
                return self.js(api_file(q.get('p', [''])[0], q.get('full', [''])[0] == '1'))
            if u.path == '/api/backlinks':
                return self.js(api_backlinks(q.get('p', [''])[0]))
            if u.path == '/api/kalender':
                return self.js(api_kalender(q.get('von', ['0000-00-00'])[0], q.get('bis', ['9999-99-99'])[0]))
            if u.path == '/api/usage':
                return self.js(api_usage(q.get('window', ['7d'])[0]))
            if u.path == '/api/plugins':
                return self.js(api_plugins(q.get('url', [''])[0]))
            if u.path == '/api/chat':
                return self.js(JOBS.get(q.get('id', [''])[0], {'error': 'unbekannter Job'}))
            if u.path == '/api/mail/folders':
                return self.js(api_mail_folders(q.get('token', [''])[0], q.get('account', [''])[0]))
            if u.path == '/api/mail/prefs':
                return self.js(api_mail_prefs(q.get('token', [''])[0], q.get('account', [''])[0]))
            if u.path == '/api/mail/messages':
                return self.js(api_mail_messages(q.get('token', [''])[0], q.get('account', [''])[0], q.get('folder', [''])[0],
                                                 int(q.get('offset', ['0'])[0]), int(q.get('limit', ['30'])[0])))
            if u.path == '/api/mail/message':
                return self.js(api_mail_message(q.get('token', [''])[0], q.get('account', [''])[0],
                                                q.get('folder', [''])[0], q.get('uid', [''])[0]))
            if u.path == '/api/mail/attachment':
                token = q.get('token', [''])[0]
                if not mail_check(token):   # sonst 404 fuer ein abgelaufenes Token -- wie bei jedem anderen Mail-Endpunkt
                    return self.js({'error': 'gesperrt', 'auth': True}, 401)
                payload, ctype, fn = mail_attachment_bytes(token, q.get('account', [''])[0], q.get('folder', [''])[0],
                                                            q.get('uid', [''])[0], int(q.get('idx', ['0'])[0]))
                if payload is None:
                    return self.js({'error': 'Anhang nicht gefunden'}, 404)
                # Kopfzeilen sind Latin-1: "Rechnung €.pdf" warf erst NACH dem 200 und hing ein 500 an.
                # Darum ASCII-Ersatzname plus filename*=UTF-8''... (RFC 5987) fuer den echten Namen.
                fn = fn or 'anhang'
                ersatz = re.sub(r'[\r\n"]', '_', fn).encode('ascii', 'replace').decode('ascii').replace('?', '_')
                # Derselbe Latin-1-Stolperstein trifft den Content-Type: ein kaputter MIME-Kopf (8-Bit-Bytes,
                # fehlendes Semikolon vor einem Umlaut-Dateinamen) liefert sonst einen Wert, der erst beim
                # Schreiben des Headers scheitert -- nach dem 200 also wieder ein angehaengtes 500.
                if not re.match(r'^[\w.+-]+/[\w.+-]+$', ctype or '', re.ASCII):
                    ctype = 'application/octet-stream'
                return self.out(payload, ctype,
                                headers={'Content-Disposition': 'attachment; filename="%s"; filename*=UTF-8\'\'%s'
                                                                % (ersatz, quote(fn, safe=''))})
            if u.path in GETS:
                return self.js(GETS[u.path]())
            self.send_error(404)
        except Exception as e:
            self.js({'error': '%s: %s' % (e.__class__.__name__, e)}, 500)
    def do_POST(self):
        u = urlparse(self.path)
        ok, grund = self.darf_durch(u.path)
        if not ok:
            return self.zugang_abweisen(grund, False)
        if not origin_ok(self.headers.get('Origin')):
            abweisung_merken('origin', self.klient_ip(), self.headers.get('Origin'))
            return self.js({'error': 'Anfrage von fremder Seite abgewiesen'}, 403)
        try:
            d = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0)) or 0) or b'{}')
            # Anmelden/Einrichten setzen das Sitzungs-Keks gleich mit
            if u.path in ('/api/zugang/anmelden', '/api/zugang/einrichten'):
                r = (api_zugang_anmelden(d, self.klient_ip()) if u.path.endswith('anmelden')
                     else api_zugang_einrichten(d))
                if r.get('token'):
                    self.setze_zugang_keks(r['token'])
                return self.js(r)
            if u.path == '/api/zugang/aendern':
                d = dict(d, token=d.get('token') or self.token_aus_anfrage())
                r = api_zugang_aendern(d, self.klient_ip())
                if r.get('token'):
                    self.setze_zugang_keks(r['token'])
                return self.js(r)
            if u.path == '/api/zugang/abmelden':
                zugang_abmelden(self.token_aus_anfrage())
                self.extra_headers = {'Set-Cookie': 'puox_zugang=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax'}
                return self.js({'ok': True})
            if u.path == '/api/mail/unlock':      # braucht die IP fuer die PIN-Bremse
                return self.js(api_mail_unlock(d, self.klient_ip()))
            if u.path in POSTS:
                return self.js(POSTS[u.path](d))
            self.send_error(404)
        except Exception as e:
            self.js({'error': '%s: %s' % (e.__class__.__name__, e)}, 500)
    def js(self, obj, code=200):
        self.out(json.dumps(obj, ensure_ascii=False).encode('utf-8'), 'application/json', code)
    def out(self, data, mime, code=200, headers=None):
        self.send_response(code)
        texty = mime.startswith('text/') or mime in ('application/json', 'image/svg+xml')
        self.send_header('Content-Type', mime + ('; charset=utf-8' if texty else ''))
        self.send_header('Content-Length', str(len(data)))
        # Nichts aus dem Vault gehoert in einen Proxy- oder Browser-Cache
        self.send_header('Cache-Control', 'no-store')
        for k, v in {**(getattr(self, 'extra_headers', None) or {}), **(headers or {})}.items():
            self.send_header(k, v)
        self.end_headers()
        for i in range(0, len(data), SCHREIB_STUECK):
            self.wfile.write(data[i:i + SCHREIB_STUECK])
    def log_message(self, *a): pass

ABWEISUNGEN = os.path.join(BASE, 'abweisungen.log')

def abweisung_merken(grund, ip, host):
    """Jede Abweisung mit der TATSAECHLICHEN Quelladresse festhalten.

    Ohne das raet man, mit welcher Adresse eine Anfrage ankommt -- und genau daran
    scheitert die Fehlersuche leicht, etwa wenn die Firewall-Regel
    10.8.0.0/24 erlaubt, das Paket aber mit einer LAN-Adresse eintrifft.
    Wer abgewiesen wird, steht damit schwarz auf weiss statt in einer Vermutung.

    Bewusst schlicht: eine Zeile je Abweisung, Deckel bei 500 Zeilen, Fehler beim
    Schreiben werden verschluckt -- ein kaputtes Protokoll darf nie eine Anfrage kippen.
    """
    try:
        zeile = '%s\t%s\t%s\n' % (grund, ip, (host or '-')[:80])
        alt = []
        if os.path.exists(ABWEISUNGEN):
            with open(ABWEISUNGEN, encoding='utf-8', errors='replace') as fh:
                alt = fh.readlines()[-499:]
        with open(ABWEISUNGEN, 'w', encoding='utf-8') as fh:
            fh.writelines(alt)
            fh.write(zeile)
    except OSError:
        pass

def host_ok(kopf):
    """Traegt die Anfrage den einen gueltigen Namen? Der Host-Kopf darf einen Port
    tragen (os.example.com:443), Grossschreibung ist egal, und ein IPv6-Literal kommt in
    eckigen Klammern -- das ist nie ein Name und faellt damit ohnehin durch.
    Fehlt der Kopf ganz (HTTP/1.0), ist das ebenfalls kein Treffer."""
    h = (kopf or '').strip().lower()
    if h.startswith('['):
        return False
    if ':' in h:
        h = h.rsplit(':', 1)[0]
    return h == NAME.lower()

def origin_ok(kopf):
    """CSRF-Schutz fuer POST. Fehlt der Origin-Kopf (curl, Skripte), entscheidet allein die
    PIN-Sitzung; ist er da, muss er genau die eigene Adresse sein. SameSite=Lax allein reicht
    nicht: jede Seite unter *.example.com gilt fuer den Browser als "same-site"."""
    eigen = 'https://%s' % NAME + ('' if PORT == 443 else ':%d' % PORT)
    return not kopf or kopf.strip().lower() == eigen.lower()

def tls_kontext():
    """Fehlt das Zertifikat, wirft load_cert_chain -- der Start bricht dann ab, statt
    still auf Klartext zurueckzufallen. Ein solcher Rueckfall waere gefaehrlicher als
    ein klarer Abbruch, weil man sich faelschlich fuer verschluesselt haelt."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(TLS_CERT, TLS_KEY)
    return ctx

class Weiterleitung(BaseHTTPRequestHandler):
    """Port 80 antwortet nur noch mit 301 auf https. Kein Klartext-Pfad bleibt offen."""
    server_version = 'PUOX-OS'
    def do_GET(self):
        self.send_response(301)
        self.send_header('Location', 'https://%s%s' % (NAME, self.path))
        self.send_header('Content-Length', '0')
        self.end_headers()
    do_POST = do_HEAD = do_GET
    def log_message(self, *a): pass

def eigene_adressen():
    """Adressen, auf denen PUOX-OS neben einem fremden Server erreichbar sein soll.

    127.0.0.1 steht bewusst ZUERST und immer: Der hosts-Eintrag auf diesem Rechner
    zeigt dorthin, und nur so bleibt das Dashboard hier erreichbar,
    wenn der WireGuard-Tunnel gerade nicht steht. Danach die eigenen Netzadressen,
    darunter die Tunnel-IP -- ueber die kommen die anderen Geraete.

    Hier wird bewusst BREIT gebunden, auch die LAN-Adresse. Wer tatsaechlich
    durchkommt, entscheidet allein netzzugang.json (Modus vpn: nur Tunnelnetz +
    localhost, alles andere 403) plus die Firewall-Regel. Wuerde die Auswahl schon
    hier getroffen, stuende dieselbe Entscheidung an zwei Stellen und liefe
    auseinander -- geprueft 17.09.2026: Zugriff ueber 192.168.178.20 endet mit 403."""
    adr = ['127.0.0.1']
    for ip in NETZ_EIGENE():
        if ip not in adr:
            adr.append(ip)
    return adr

def binde(adressen, port, handler, tls=False):
    """Denselben Handler auf mehreren Adressen desselben Ports bedienen.

    Warum ueberhaupt mehrere: haelt etwa ein lokaler nginx 0.0.0.0:443 UND 0.0.0.0:80 --
    also auch 127.0.0.1. Windows laesst daneben adress-spezifische Sockets zu, und
    der spezifischere gewinnt fuer seine Adresse. PUOX-OS bindet deshalb jede
    Adresse einzeln statt der Wildcard; nginx behaelt den Rest.

    Jede Adresse einzeln und fehlertolerant: eine belegte Adresse darf die anderen
    nicht mitreissen. Gibt die tatsaechlich laufenden Server zurueck."""
    class _Still(ThreadingHTTPServer):
        # Der Handshake laeuft seit do_handshake_on_connect=False erst beim ersten rfile.readline
        # im Handler-Thread -- ein ssl.SSLError dort (Klartext-HTTP auf dem TLS-Port, abgelehntes
        # selbstsigniertes Zertifikat) und ein schlichter Verbindungsabbruch sind normale Vorkommnisse,
        # kein Serverfehler, und sollen deshalb keinen Traceback ins Log schreiben (sonst wie bisher).
        def handle_error(self, request, client_address):
            if isinstance(sys.exc_info()[1], (ssl.SSLError, ConnectionError, TimeoutError)):
                return
            super().handle_error(request, client_address)
    ctx = tls_kontext() if tls else None
    laeuft = []
    for adr in adressen:
        try:
            srv = _Still((adr, port), handler)
        except OSError as e:
            print('  %s:%d nicht belegbar (%s)' % (adr, port, e))
            continue
        if ctx is not None:
            try:
                # Handshake NICHT im Annahme-Thread: dort blockierte ein stummer TCP-Client jede
                # weitere Verbindung. So laeuft er im Handler-Thread unter H.timeout.
                srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
            except (ssl.SSLError, OSError) as e:
                print('  %s:%d: TLS fehlgeschlagen (%s)' % (adr, port, e))
                srv.server_close()
                continue
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        laeuft.append(adr)
    return laeuft

def auf_port(port):
    """Wer sitzt auf dem Port: '' = frei, 'puox-os' = wir selbst, sonst der Server-Kopf
    des Fremden. Windows erlaubt mit SO_REUSEADDR ein ZWEITES bind auf denselben Port --
    dann laufen zwei Server dort und es ist Zufall, welcher antwortet; darum aktiv
    anklopfen. Nur zu fragen OB der Port belegt ist, reichte nicht: lief ein fremder nginx
    auf 80, meldete der Start "PUOX-OS laeuft bereits" und oeffnete dessen Fehlerseite
    (2026-09-15)."""
    import socket
    s = socket.socket()
    s.settimeout(0.4)
    try:
        if s.connect_ex(('127.0.0.1', port)) != 0:
            return ''
    finally:
        s.close()
    # Auf dem TLS-Port muss https geklopft werden, sonst antwortet dort nichts Lesbares.
    # Zertifikat absichtlich ungeprueft: wir fragen nur nach dem Server-Kopf, und beim
    # selbstsignierten Zertifikat waere jede Pruefung von vornherein zwecklos.
    if port == PORT:
        adr, ctx = 'https://127.0.0.1:%d/' % port, ssl._create_unverified_context()
    else:
        adr, ctx = 'http://127.0.0.1:%d/' % port, None
    try:
        # Host-Kopf mitgeben: unsere eigene Instanz weist sonst mit 421 ab. Die Antwort
        # traegt den Server-Kopf zwar auch dann, aber so ist der Klopftest ehrlich.
        anfrage = urllib.request.Request(adr, headers={'Host': NAME})
        with urllib.request.urlopen(anfrage, timeout=2, context=ctx) as r:
            kopf = r.headers.get('Server', '?')
    except urllib.error.HTTPError as e:
        kopf = e.headers.get('Server', '?')
    except Exception:
        kopf = '?'
    # BaseHTTP: eine noch laufende Fassung von vor dem eigenen Server-Kopf
    return 'puox-os' if kopf.startswith(('PUOX-OS', 'BaseHTTP')) else kopf

if __name__ == '__main__':
    adresse = 'https://%s' % NAME + ('' if PORT == 443 else ':%d' % PORT)
    # Zertifikat zuerst pruefen, vor jedem bind: fehlt es, bricht der Start ab und nennt
    # die erwarteten Pfade. Ein stiller Rueckfall auf HTTP waere gefaehrlicher als der
    # Abbruch -- man haelt sich sonst faelschlich fuer verschluesselt.
    if not (os.path.exists(TLS_CERT) and os.path.exists(TLS_KEY)):
        print('Kein Zertifikat gefunden - PUOX-OS startet nicht.')
        print('  erwartet:  %s' % TLS_CERT)
        print('             %s' % TLS_KEY)
        print('  Neu erzeugen (Git Bash, laeuft 10 Jahre):')
        print('    cd 97_puoxos/tls')
        print('    MSYS_NO_PATHCONV=1 openssl req -x509 -newkey rsa:4096 -nodes \\')
        print('      -keyout privkey.pem -out fullchain.pem -days 3650 \\')
        print('      -subj "/CN=%s" -addext "subjectAltName=DNS:%s" \\' % (NAME, NAME))
        print('      -addext "basicConstraints=critical,CA:FALSE" \\')
        print('      -addext "keyUsage=critical,digitalSignature,keyEncipherment" \\')
        print('      -addext "extendedKeyUsage=serverAuth"')
        print('  Selbstsigniert: jedes Geraet bestaetigt die Ausnahme EINMAL. Verschluesselt ist')
        print('  das genauso stark wie Let\'s Encrypt - der Browser kennt nur den Aussteller nicht.')
        sys.exit(1)
    sitzt = auf_port(PORT)
    if sitzt == 'puox-os':
        print('PUOX-OS laeuft bereits auf %s - dieses Fenster kann zu.' % adresse)
        if '--nobrowser' not in sys.argv:
            webbrowser.open(adresse)
        sys.exit(0)
    if HOST == '0.0.0.0':
        # IMMER die Einzeladressen, nie die Wildcard -- auch wenn der Port gerade frei ist.
        #
        # Windows laesst adress-spezifische Sockets neben einem fremden 0.0.0.0-Socket zu,
        # und der spezifischere gewinnt fuer seine Adresse. Umgekehrt gilt das aber nicht:
        # Haette PUOX-OS die Wildcard, kaeme ein fremder Webserver (z. B. nginx) beim naechsten Start
        # nicht mehr hoch -- und die Ursache waere nicht erkennbar, weil dann die
        # lokale Website nicht ginge und PUOX-OS unschuldig aussaehe. Mit Einzeladressen
        # starten beide nebeneinander, in beliebiger Reihenfolge.
        #
        # 127.0.0.1 steht dabei zuerst: die hosts-Zeile zeigt dorthin, und nur so bleibt
        # das Dashboard hier erreichbar, wenn der Tunnel nicht steht.
        ziele = eigene_adressen()
        if sitzt:
            print('Auf Port %d antwortet ein fremder Server (%s) - PUOX-OS bindet daneben.'
                  % (PORT, sitzt))
    else:
        ziele = [HOST]   # ausdruecklich gesetzt, z. B. set HOST=127.0.0.1
    sessions_laden()      # angemeldete Geraete bleiben ueber einen Neustart hinweg angemeldet
    threading.Thread(target=uptime_loop, daemon=True).start()
    threading.Thread(target=backup_loop, daemon=True).start()
    threading.Thread(target=mail_poll_loop, daemon=True).start()
    ThreadingHTTPServer.allow_reuse_address = False  # kein stiller Zweit-Server auf demselben Port
    laufend = binde(ziele, PORT, H, tls=True)
    if not laufend:
        print('Keine einzige Adresse auf Port %d belegbar - PUOX-OS startet nicht.' % PORT)
        print('Fremden Server beenden oder mit anderem Port starten:  set PORT=8443 && python server.py')
        sys.exit(1)
    # Port 80 ist reine Bequemlichkeit: laesst er sich nicht binden,
    # laeuft PUOX-OS auf 443 weiter. Ein harter Abbruch waere ein Selbstblockierer.
    leitet = binde(ziele, PORT_HTTP, Weiterleitung)
    if '--nobrowser' not in sys.argv:
        threading.Timer(0.6, lambda: webbrowser.open(adresse)).start()
    print('PUOX-OS laeuft.  (Strg+C beendet)')
    print('  Adresse:    %s' % adresse)
    print('              ausschliesslich dieser Name - andere Namen, localhost und jeder')
    print('              IP-Zugriff werden mit 421 abgewiesen.')
    print('  gebunden:   %s  (Port %d)' % (', '.join(laufend), PORT))
    if leitet:
        print('  Weiterleitung auf Port %d: %s' % (PORT_HTTP, ', '.join(leitet)))
    else:
        print('  Weiterleitung auf Port %d entfaellt - Port belegt. Nur Bequemlichkeit.' % PORT_HTTP)
    print('  Zugang:     %s' % ('PIN wird beim ersten Aufruf gesetzt' if not zugang_eingerichtet()
                                else 'PIN-geschuetzt (auch lokal)'))
    # Alle Server laufen in eigenen Daemon-Threads (siehe binde()). Der Hauptthread
    # haelt den Prozess nur am Leben und faengt Strg+C ab.
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print('PUOX-OS beendet.')
