#!/usr/bin/env python3
"""Selbstcheck fuer die nicht-trivialen Stellen in server.py -- kein Framework, einfach ausfuehren:
    python 97_puoxos/test_server.py
Faellt eine Zusicherung, ist die Logik kaputt; sonst kommt "alles gruen"."""
import json
import os
import re
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import server  # noqa: E402

# Die Zugangs-Tests legen Sitzungen an. Ohne diese Umleitung schrieben sie in die ECHTE
# Secrets/sitzungen.json und haetten dort Test-Sitzungen hinterlassen.
import tempfile  # noqa: E402
server.SESSION_FILE = os.path.join(tempfile.gettempdir(), 'puox-test-sitzungen.json')
server.ZUGANG_SESSIONS.clear()
# Ebenso der Schrift-Rundlauf: er legte eine Datei im versionierten Schriftordner an und schrieb
# beim Entfernen theme.json neu.
_TMP = tempfile.mkdtemp(prefix='puox-test-')
server.SCHRIFT_DIR = os.path.join(_TMP, 'schriften')
server.THEME_FILE = os.path.join(_TMP, 'theme.json')
# Zugang, Mail, Kalender, OPNsense, Termine und das Abweisungsprotokoll: die Tests unten schreiben
# und zerstoeren diese Dateien absichtlich -- nie die echten in der Sperrzone bzw. in 97_puoxos/.
server.MAIL_DIR = _TMP
for _name, _datei in (('ZUGANG_FILE', 'zugang.json'), ('MAIL_FILE', 'mail.json'), ('KAL_FILE', 'kalender.json'),
                      ('OPN_FILE', 'opnsense.json'), ('TERMINE_JSON', 'termine.json'),
                      ('LOKAL_TERMINE', 'termine.txt'), ('ABWEISUNGEN', 'abweisungen.log')):
    setattr(server, _name, os.path.join(_TMP, _datei))


def _zugang_pin(pin='1234abcd'):
    """Legt eine Test-zugang.json an und liefert ein gueltiges Sitzungs-Token."""
    import base64
    salt = b's' * 16
    open(server.ZUGANG_FILE, 'w', encoding='utf-8').write(json.dumps(
        {'salt': base64.b64encode(salt).decode('ascii'), 'hash': server._pin_hash(pin, salt)}))
    return server.zugang_neuer_token()


def _anfrage(methode, pfad, kopf=None, body=b''):
    """Ruft do_GET/do_POST ohne Socket auf; liefert {'code', 'data'}. Netz steht auf 'lan'."""
    import io
    h = server.H.__new__(server.H)
    h.path, h.client_address = pfad, ('127.0.0.1', 5)
    h.headers = dict({'Host': server.NAME, 'Content-Length': str(len(body))}, **(kopf or {}))
    h.rfile = io.BytesIO(body)
    raus = {}
    h.out = lambda data, mime, code=200, headers=None: raus.update(code=code, data=data)
    h.send_error = lambda code, *a: raus.update(code=code)
    echt = server.netz_cfg
    server.netz_cfg = lambda: {'modus': 'lan', 'erlaubt': []}
    try:
        getattr(h, 'do_' + methode)()
    finally:
        server.netz_cfg = echt
    return raus


def test_caldav_to_ics():
    xml = ('<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav">'
           '<d:response><d:propstat><d:prop><cal:calendar-data>'
           'BEGIN:VCALENDAR&#13;\nBEGIN:VEVENT&#13;\nDTSTART:20260807T090000&#13;\n'
           'SUMMARY:Termin mit &amp; Zeichen&#13;\nEND:VEVENT&#13;\nEND:VCALENDAR'
           '</cal:calendar-data></d:prop></d:propstat></d:response>'
           '<d:response><d:propstat><d:prop><cal:calendar-data>'
           'BEGIN:VCALENDAR\nBEGIN:VEVENT\nDTSTART:20260808\nSUMMARY:Ganztags\nEND:VEVENT\nEND:VCALENDAR'
           '</cal:calendar-data></d:prop></d:propstat></d:response></d:multistatus>')
    ics = server.caldav_to_ics(xml)
    assert ics.count('BEGIN:VEVENT') == 2, ics
    assert 'Termin mit & Zeichen' in ics, 'XML-Entities nicht aufgeloest'
    assert '&#13;' not in ics, 'CR-Entities nicht entfernt'
    # leere Antwort darf nicht knallen, sondern liefert ''
    assert server.caldav_to_ics('<d:multistatus/>') == ''


def test_ics_parsing():
    """Der Parser aus ics_events() -- hier direkt auf dem zusammengebauten ICS geprueft."""
    raw = server.caldav_to_ics(
        '<cal:calendar-data>BEGIN:VEVENT\nDTSTART;TZID=Europe/Berlin:20260807T143000\n'
        'SUMMARY:Kundentermin\nEND:VEVENT</cal:calendar-data>')
    m = re.search(r'DTSTART[^:]*:(\d{8})(?:T(\d{4}))?', raw)
    assert m and m.group(1) == '20260807' and m.group(2) == '1430', raw


def test_pin():
    ok = ['1234', '123456', '0000', 'abcd', 'Sicher2026!', 'a' * 32]
    bad = ['123', '', '12 34', '1234\n', 'a' * 33, 'ab\tcd']
    for p in ok:
        assert server.PIN_RE.match(p), p
    for p in bad:
        assert not server.PIN_RE.match(p), p


def test_backlink_name():
    """api_backlinks vergleicht ueber den Dateinamen ohne .md, klein geschrieben."""
    idx, _ = {'notizen': {'10_wiki/00_wiki.md'}}, 0
    server.BL_CACHE.update(ts=server.time.time(), idx=idx, skip=7)
    r = server.api_backlinks('10_wiki/notizen.md')
    assert r['links'] == ['10_wiki/00_wiki.md'], r
    assert r['uebersprungen'] == 7
    # die Datei selbst darf nie als eigener Backlink auftauchen
    server.BL_CACHE.update(ts=server.time.time(), idx={'x': {'a/X.md'}}, skip=0)
    assert server.api_backlinks('a/X.md')['links'] == []
    server.BL_CACHE.update(ts=0, idx=None, skip=0)  # Cache wieder freigeben


def test_autoresponder():
    """Wichtigste Regel: keine Mailschleifen. Lieber eine Antwort zu wenig als eine Schleife."""
    eigene, jetzt = ['ich@example.com'], 1_000_000.0
    erlaubt = server.auto_antworten_erlaubt
    assert erlaubt({'From': 'a@b.de'}, 'a@b.de', eigene, {}, jetzt)
    # an sich selbst: nie
    assert not erlaubt({}, 'ich@example.com', eigene, {}, jetzt)
    assert not erlaubt({}, 'ICH@EXAMPLE.COM', eigene, {}, jetzt), 'Gross/Kleinschreibung ignorieren'
    # Automaten und Listen: nie
    assert not erlaubt({'Auto-Submitted': 'auto-replied'}, 'a@b.de', eigene, {}, jetzt)
    assert not erlaubt({'Precedence': 'bulk'}, 'a@b.de', eigene, {}, jetzt)
    assert not erlaubt({'List-Id': '<x.lists.de>'}, 'a@b.de', eigene, {}, jetzt)
    assert not erlaubt({'List-Unsubscribe': '<mailto:x>'}, 'a@b.de', eigene, {}, jetzt)
    assert not erlaubt({'Return-Path': '<>'}, 'a@b.de', eigene, {}, jetzt), 'Bounce nie beantworten'
    # Sperrfrist je Absender
    log = {'a@b.de': jetzt - 3600}
    assert not erlaubt({}, 'a@b.de', eigene, log, jetzt), '1 h danach noch gesperrt'
    assert erlaubt({}, 'a@b.de', eigene, log, jetzt + 24 * 3600), 'nach 24 h wieder erlaubt'
    # Muell-Absender
    assert not erlaubt({}, '', eigene, {}, jetzt)
    assert not erlaubt({}, 'kein-at-zeichen', eigene, {}, jetzt)


def test_theme_validierung():
    th = server.api_theme()
    assert server.HEX_RE.match(th['mint2']), 'zweite Akzentfarbe fehlt'
    assert 8 <= th['fs_body'] <= 32, 'Fliesstext-Groesse ausserhalb 8-32'
    assert 12 <= th['fs_head'] <= 36, 'Ueberschrift-Groesse ausserhalb 12-36'
    erlaubt = server.FONTS + server.schrift_namen()   # eigene Schriften zaehlen mit
    assert th['font_head'] in erlaubt
    assert th['font_body'] in erlaubt or th['font_body'] == '', 'leer = erbt Ueberschrift'
    assert th['menue'] in ('puox', 'burger')
    assert th['burger_pos'] in ('links', 'rechts', 'oben')
    assert th['zeitformat'] in (12, 24)
    assert not server.HEX_RE.match('#fff'), 'Kurzform darf nicht durchgehen'
    assert not server.HEX_RE.match('#21F1A8\n'), 'Zeilenumbruch darf nicht durchgehen'
    # Werte ausserhalb der Grenzen werden geklemmt, nicht uebernommen
    geklemmt = server._clamp_int(999, 8, 32, 14)
    assert geklemmt == 32, geklemmt
    assert server._clamp_int('unsinn', 8, 32, 14) == 14


def test_termin_pruefe():
    t, err = server.termin_pruefe({'titel': 'Test', 'beginn': '2026-08-14T09:00',
                                   'ende': '2026-08-14T10:00', 'kategorie': 'kunde'})
    assert err is None, err
    assert t['kategorie'] == 'kunde' and t['id'], t
    assert server.termin_pruefe({'titel': '', 'beginn': '2026-08-14'})[1], 'Titel fehlt muss meckern'
    assert server.termin_pruefe({'titel': 'X', 'beginn': 'quatsch'})[1], 'kaputtes Datum muss meckern'
    assert server.termin_pruefe({'titel': 'X', 'beginn': '2026-08-14T10:00',
                                 'ende': '2026-08-14T09:00'})[1], 'Ende vor Beginn muss meckern'
    # unbekannte Kategorie faellt auf die Voreinstellung zurueck
    t2, _ = server.termin_pruefe({'titel': 'X', 'beginn': '2026-08-14', 'kategorie': 'erfunden'})
    assert t2['kategorie'] == 'termin', t2['kategorie']


def test_termin_wiederholung():
    vor = server.termin_vorkommen
    einmal = {'beginn': '2026-08-14', 'wiederholung': ''}
    assert vor(einmal, '2026-08-01', '2026-08-31') == ['2026-08-14']
    assert vor(einmal, '2026-09-01', '2026-09-30') == []
    woech = {'beginn': '2026-08-03', 'wiederholung': 'woechentlich'}
    assert vor(woech, '2026-08-01', '2026-08-31') == ['2026-08-03', '2026-08-10', '2026-08-17', '2026-08-24', '2026-08-31']
    # Werktags laesst Samstag/Sonntag aus (8.8.2026 = Samstag)
    werk = vor({'beginn': '2026-08-03', 'wiederholung': 'werktags'}, '2026-08-03', '2026-08-09')
    assert werk == ['2026-08-03', '2026-08-04', '2026-08-05', '2026-08-06', '2026-08-07'], werk
    # Monatlich ueber den Monatsletzten: 31.01. -> 28.02.
    mon = vor({'beginn': '2026-01-31', 'wiederholung': 'monatlich'}, '2026-02-01', '2026-02-28')
    assert mon == ['2026-02-28'], mon
    # wdh_bis beendet die Serie
    bis = vor({'beginn': '2026-08-03', 'wiederholung': 'woechentlich', 'wdh_bis': '2026-08-12'},
              '2026-08-01', '2026-08-31')
    assert bis == ['2026-08-03', '2026-08-10'], bis


def test_port_belegt():
    assert server.auf_port(1) == '', 'Port 1 sollte frei/geschlossen sein'
    """Ein fremder Server auf dem Port darf nicht als PUOX-OS durchgehen -- sonst
    meldet der Start "laeuft bereits" und oeffnet dessen Fehlerseite."""
    import threading
    from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
    class Fremd(BaseHTTPRequestHandler):
        server_version = 'nginx'
        sys_version = ''
        def do_GET(self): self.send_response(404); self.end_headers()
        def log_message(self, *a): pass
    srv = ThreadingHTTPServer(('127.0.0.1', 0), Fremd)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        assert server.auf_port(srv.server_address[1]).startswith('nginx'), 'fremder Server muss als fremd gelten'
    finally:
        srv.shutdown()


def test_zugang_sitzung():
    """Token-Verwaltung: gueltig bis Ablauf, danach tot; abgemeldete Token gelten nicht mehr."""
    import time as _t
    tok = server.zugang_neuer_token()
    assert server.zugang_pruefe(tok), 'frischer Token muss gelten'
    assert not server.zugang_pruefe('erfunden'), 'unbekannter Token darf nicht gelten'
    assert not server.zugang_pruefe(''), 'leerer Token darf nicht gelten'
    assert not server.zugang_pruefe(None), 'kein Token darf nicht gelten'
    server.ZUGANG_SESSIONS[server._tok_hash(tok)] = _t.time() - 1     # kuenstlich abgelaufen
    assert not server.zugang_pruefe(tok), 'abgelaufener Token darf nicht mehr gelten'
    tok2 = server.zugang_neuer_token()
    server.zugang_abmelden(tok2)
    assert not server.zugang_pruefe(tok2), 'abgemeldeter Token darf nicht mehr gelten'


def test_zugang_token_nur_als_hash():
    """Auf Platte darf nie der Token selbst stehen -- nur sein Hash. Sonst waere die Datei
    ein fertiger Generalschluessel fuer jeden, der sie liest."""
    tok = server.zugang_neuer_token()
    assert tok not in server.ZUGANG_SESSIONS, 'Klartext-Token gehoert nicht in die Sitzungstabelle'
    assert server._tok_hash(tok) in server.ZUGANG_SESSIONS
    if os.path.isfile(server.SESSION_FILE):
        inhalt = open(server.SESSION_FILE, encoding='utf-8').read()
        assert tok not in inhalt, 'Klartext-Token darf nicht in sitzungen.json landen'
        assert server._tok_hash(tok) in inhalt, 'Hash sollte gespeichert sein'
    server.zugang_abmelden(tok)


def test_zugang_sitzung_ueberlebt_neustart():
    """sessions_laden() holt gueltige Sitzungen zurueck, abgelaufene nicht."""
    import time as _t
    tok = server.zugang_neuer_token()
    h = server._tok_hash(tok)
    alt_tok = 'abgelaufen-xyz'
    server.ZUGANG_SESSIONS[server._tok_hash(alt_tok)] = _t.time() - 10
    server.sessions_sichern()                       # abgelaufene fliegen beim Sichern raus
    server.ZUGANG_SESSIONS.clear()                  # wie ein Neustart
    server.sessions_laden()
    assert server.zugang_pruefe(tok), 'gueltige Sitzung muss den Neustart ueberleben'
    assert not server.zugang_pruefe(alt_tok), 'abgelaufene Sitzung darf nicht zurueckkommen'
    server.zugang_abmelden(tok)


def test_ip_passt():
    """CIDR-Vergleich -- die Grundlage der Zugangsliste."""
    assert server.ip_passt('10.8.0.5', '10.8.0.5')
    assert not server.ip_passt('10.8.0.6', '10.8.0.5')
    assert server.ip_passt('10.8.0.5', '10.8.0.0/24')
    assert not server.ip_passt('10.8.1.5', '10.8.0.0/24')
    assert server.ip_passt('10.8.1.5', '10.8.0.0/16')
    assert server.ip_passt('1.2.3.4', '0.0.0.0/0'), '/0 umfasst alles'
    assert server.ip_passt('192.168.178.20', '192.168.178.20/32')
    # Unsinn darf nie durchgehen
    for kaputt in ['10.8.0.0/33', '10.8.0.0/-1', '10.8.0.0/abc', '999.1.1.1/24', 'quatsch']:
        assert not server.ip_passt('10.8.0.5', kaputt), kaputt


def test_zugang_netzgrenze():
    """Die drei Modi aus netzzugang.json: lan (eigenes /24), vpn (nur Liste + localhost), liste (nur Liste)."""
    echt = server.netz_cfg
    def stell(modus, erlaubt):
        server.netz_cfg = lambda: {'modus': modus, 'erlaubt': erlaubt}
    try:
        # --- lan: localhost und eigenes /24 ---
        stell('lan', [])
        assert server.ip_im_eigenen_netz('127.0.0.1')
        assert server.ip_im_eigenen_netz('::1')
        assert not server.ip_im_eigenen_netz('8.8.8.8'), 'fremde oeffentliche IP muss draussen bleiben'
        assert not server.ip_im_eigenen_netz('10.13.37.5'), 'fremdes Subnetz muss draussen bleiben'
        eigene = server.NETZ_EIGENE()
        if eigene:
            praefix = eigene[0].rsplit('.', 1)[0]
            assert server.ip_im_eigenen_netz(praefix + '.99'), 'Nachbar im eigenen /24 ist erlaubt'
        # --- vpn: NUR die eingetragenen Netze, localhost bleibt drin ---
        stell('vpn', ['10.8.0.0/24'])
        assert server.ip_im_eigenen_netz('127.0.0.1'), 'eigener Rechner bleibt erreichbar'
        assert server.ip_im_eigenen_netz('10.8.0.7'), 'VPN-Adresse muss durch'
        assert not server.ip_im_eigenen_netz('192.168.178.50'), 'LAN muss jetzt draussen bleiben'
        assert not server.ip_im_eigenen_netz('10.8.1.7'), 'anderes /24 bleibt draussen'
        # --- liste: wirklich nur die Liste ---
        stell('liste', ['10.8.0.7'])
        assert server.ip_im_eigenen_netz('10.8.0.7')
        assert not server.ip_im_eigenen_netz('10.8.0.8')
        assert not server.ip_im_eigenen_netz('127.0.0.1'), 'bei liste muss auch localhost drinstehen'
    finally:
        server.netz_cfg = echt


def test_zugang_pin_bremse():
    """Nach ZUGANG_MAX Fehlversuchen wird die IP fuer eine Weile gesperrt."""
    server.ZUGANG_VERSUCHE.clear()
    ip = '192.0.2.77'
    echt = server.zugang_data
    server.zugang_data = lambda: {'salt': server.base64.b64encode(b'x' * 16).decode('ascii'),
                                  'hash': 'passt-nie'}
    try:
        for _ in range(server.ZUGANG_MAX):
            r = server.api_zugang_anmelden({'pin': 'falsch'}, ip)
            assert r.get('error'), r
        gesperrt = server.api_zugang_anmelden({'pin': 'falsch'}, ip)
        assert 'Fehlversuche' in gesperrt.get('error', ''), gesperrt
        # andere IP ist davon nicht betroffen
        andere = server.api_zugang_anmelden({'pin': 'falsch'}, '192.0.2.78')
        assert 'Fehlversuche' not in andere.get('error', ''), andere
    finally:
        server.zugang_data = echt
        server.ZUGANG_VERSUCHE.clear()


def test_schrift_datei():
    """Der Auslieferungspfad /schrift/<datei> darf nur echte Schriftdateien aus dem Schriftordner
    freigeben -- kein Pfadwechsel, keine fremde Endung."""
    assert server.schrift_datei('../server.py') is None, 'Pfadwechsel muss abprallen'
    assert server.schrift_datei('..\\theme.json') is None, 'Pfadwechsel muss abprallen'
    assert server.schrift_datei('theme.json') is None, 'fremde Endung muss abprallen'
    assert server.schrift_datei('') is None
    assert server.schrift_datei('gibtsnicht.ttf') is None, 'nicht vorhandene Datei'
    # Ein echter Rundlauf: anlegen, finden, entfernen
    import base64
    r = server.api_schrift_save({'name': 'PuoxTest.woff2', 'data': base64.b64encode(b'x' * 20).decode()})
    assert r.get('ok'), r
    assert 'PuoxTest' in server.schrift_namen()
    assert server.schrift_datei('PuoxTest.woff2'), 'gerade angelegte Schrift nicht gefunden'
    assert server.api_schrift_remove({'datei': 'PuoxTest.woff2'}).get('ok')
    assert 'PuoxTest' not in server.schrift_namen()
    assert server.api_schrift_save({'name': 'boese.exe', 'data': ''}).get('error'), 'Endung nicht geprueft'


def test_explorer_sperrzone():
    """Der Explorer listet den ganzen Vault -- aber nie die Zugangsdaten und nie Dateiinhalte."""
    d = server.api_explorer()
    pfade = [f['path'] for f in d['dateien']]
    assert d['anzahl'] == len(pfade) and pfade, 'leere Dateiliste'
    # klein vergleichen: der Ordner heisst `secrets`, die gross geschriebene Pruefung war blind dafuer
    assert not [p for p in pfade if '/secrets/' in p.lower() or p.lower().startswith('secrets/')], 'Secrets ausgeliefert'
    assert not [p for p in pfade if p.startswith('.') or '/.' in p], 'Punkt-Ordner ausgeliefert'
    assert not [p for p in pfade if '__pycache__' in p]
    assert any('/' not in p for p in pfade), 'Vault-Wurzel fehlt'
    assert all(set(f) == {'path', 'bytes', 'mtime'} for f in d['dateien']), 'mehr als Metadaten geliefert'


def test_aufgabe_ablage():
    """Neue Aufgaben landen in intern/ bzw. kunden/<kunde>/offen/, Dateiname klein;
    der Kunde muss exakt ein vorhandener Ordnername unter 02_kunden/ sein (kunde wird Teil des
    Pfads) -- Umlaute, `&` und Klammern erlaubt die Konvention."""
    echt = server.VAULT
    server.VAULT = tempfile.mkdtemp(prefix='puox-test-vault-')
    try:
        os.makedirs(os.path.join(server.VAULT, '02_kunden', 'demo-kunde'))
        os.makedirs(os.path.join(server.VAULT, '02_kunden', 'müller-&-söhne-(gmbh)'))
        r = server.api_task_new({'titel': 'Neue  Aufgabe Für Test', 'prioritaet': 'hoch'})
        assert r.get('path') == '09_aufgaben/intern/neue-aufgabe-für-test.md', r
        r = server.api_task_new({'titel': 'Logo tauschen', 'kunde': 'demo-kunde'})
        assert r.get('path') == '09_aufgaben/kunden/demo-kunde/offen/logo-tauschen.md', r
        assert 'kunde: "[[demo-kunde]]"' in open(os.path.join(server.VAULT, r['path']), encoding='utf-8').read()
        r = server.api_task_new({'titel': 'Angebot', 'kunde': 'müller-&-söhne-(gmbh)'})
        assert r.get('path') == '09_aufgaben/kunden/müller-&-söhne-(gmbh)/offen/angebot.md', r
        for boese in ('../../x', 'gibts-nicht', 'Demo-Kunde', '.', '..', 'demo-kunde/../..', '02_kunden'):
            assert server.api_task_new({'titel': 'x', 'kunde': boese}).get('error'), boese
        # Kundenname: Bindestrich-Laeufe zusammenziehen, `..` darf nicht aus 02_kunden hinausfuehren
        assert server.api_kunde_new({'name': 'Neu  Kunde'}).get('path') == '02_kunden/neu-kunde/neu-kunde.md'
        for boese in ('..', '-- --', '.'):
            assert server.api_kunde_new({'name': boese}).get('error'), boese
    finally:
        server.VAULT = echt


def test_zugang_freie_pfade():
    """Nur Anmeldeseite, Zugangs-Endpunkte und das Logo sind ohne Anmeldung erreichbar --
    insbesondere KEIN Datenendpunkt."""
    heikel = ['/', '/api/manifest', '/api/file', '/api/config', '/api/chat', '/api/dbupdate',
              '/api/theme', '/api/kalender', '/api/mail/status', '/api/backlinks', '/api/abteilungen',
              '/api/explorer', '/api/schriften']
    for p in heikel + ['/login']:
        assert p not in server.ZUGANG_FREI, '%s darf nicht ohne Anmeldung erreichbar sein' % p
    for p in ['/api/zugang/anmelden', '/api/zugang/status']:
        assert p in server.ZUGANG_FREI, '%s muss ohne Anmeldung erreichbar sein' % p
    # / und /login: Unangemeldete bekommen die Anmeldeseite (401), nie index.html
    tok = _zugang_pin()
    try:
        for p in ('/', '/login'):
            r = _anfrage('GET', p)
            assert r.get('code') == 401 and b'Zugangs-PIN eingeben' in r.get('data', b''), (p, r.get('code'))
            r = _anfrage('GET', p, {'Cookie': 'puox_zugang=' + tok})
            assert r.get('code') == 200 and b'Zugangs-PIN eingeben' not in r['data'], (p, r.get('code'))
    finally:
        os.remove(server.ZUGANG_FILE)
        server.zugang_abmelden(tok)


def test_host_zwang():
    """Nur NAME zaehlt -- mit und ohne Port, Grossschreibung egal. Alles andere faellt
    durch, sonst waere die eine gueltige Adresse wertlos."""
    assert server.host_ok('os.example.com')
    assert server.host_ok('os.example.com:443'), 'Port im Host-Kopf ist zulaessig'
    assert server.host_ok('OS.EXAMPLE.COM'), 'Hostnamen sind case-insensitiv'
    assert server.host_ok(' os.example.com '), 'Leerraum wird abgeschnitten'
    for falsch in ['anderer-name.example', 'localhost', 'localhost:443', '127.0.0.1', '10.8.0.3',
                   '192.168.178.20', 'os.example.com.angreifer.tld', 'xos.example.com',
                   '[::1]', '[::1]:443', '', None]:
        assert not server.host_ok(falsch), '%r darf nicht durchkommen' % (falsch,)


def test_eigene_adressen():
    """127.0.0.1 muss ZUERST und immer dabei sein. Steht der WireGuard-Tunnel nicht,
    ist sie die einzige Adresse, unter der das Dashboard auf diesem Rechner noch
    erreichbar ist. Genau daran scheiterte die erste Fassung."""
    adr = server.eigene_adressen()
    assert adr[0] == '127.0.0.1', 'Loopback muss zuerst gebunden werden, war: %r' % (adr[:1],)
    assert len(adr) == len(set(adr)), 'keine Adresse doppelt binden: %r' % (adr,)
    # Nie die Wildcard: sonst kaeme ein anderer lokaler Webserver auf demselben Port nicht mehr hoch und
    # der Dienst waere tot, ohne dass die Ursache bei PUOX-OS zu vermuten waere.
    assert '0.0.0.0' not in adr, 'Wildcard darf nie in der Bind-Liste stehen: %r' % (adr,)
    assert '::' not in adr, 'IPv6-Wildcard ebenso wenig: %r' % (adr,)


def test_tls_kontext():
    """Ohne Zertifikat wirft der Kontext -- genau daran bricht der Start ab, statt still
    auf Klartext zurueckzufallen. Liegt eines, muss es sich laden lassen."""
    import ssl as _ssl
    if os.path.exists(server.TLS_CERT) and os.path.exists(server.TLS_KEY):
        ctx = server.tls_kontext()
        assert isinstance(ctx, _ssl.SSLContext), 'tls_kontext liefert keinen SSLContext'
    else:
        try:
            server.tls_kontext()
        except (OSError, _ssl.SSLError):
            pass
        else:
            assert False, 'tls_kontext haette ohne Zertifikat werfen muessen'


def test_keks_nur_ueber_tls():
    """Secure-Flag am Sitzungs-Keks: das Token darf nie im Klartext ueber das Netz."""
    quelle = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'server.py'),
                  encoding='utf-8').read()
    for zeile in re.findall(r"'puox_zugang=[^']*'", quelle):
        assert 'Secure' in zeile, 'Set-Cookie ohne Secure-Flag: %s' % zeile


def test_write_file_atomar():
    """Bricht das Schreiben ab, bleibt das Original stehen (frueher: auf 0 Byte gekuerzt);
    Temp-Dateien bleiben nicht liegen."""
    p = os.path.join(_TMP, 'atomar.txt')
    open(p, 'wb').write(b'ALT')
    class Kaputt:                      # hat eine Laenge, laesst sich aber nicht schreiben
        def __len__(self): return 3
    try:
        server.write_file(p, None, Kaputt())
    except TypeError:
        pass
    assert open(p, 'rb').read() == b'ALT', 'Original beim Abbruch zerstoert'
    assert server.write_file(p, 'neu ä') == {'ok': True}
    assert open(p, 'rb').read() == 'neu ä'.encode('utf-8')
    assert not [f for f in os.listdir(_TMP) if f.startswith('.atomar.txt.')], 'Temp-Datei liegen geblieben'


def test_termine_kaputt_und_lock():
    """Kaputte termine.json: Schreib-Endpunkte brechen ab statt mit [] zu ueberschreiben; die
    Leseansicht zeigt den Fehler als Hinweis. Parallele Neuanlagen verlieren keinen Termin."""
    kaputt = '[{"id": "a", "titel": "wichtig", "beginn": "2026-10-05"},'
    open(server.TERMINE_JSON, 'w', encoding='utf-8').write(kaputt)
    server.TERM.update(ts=time.time() + 10 ** 6, evs=[], err='')     # keine ICS-Abrufe
    try:
        for fn, d in ((server.api_termin_new, {'titel': 'neu', 'beginn': '2026-10-06'}),
                      (server.api_termin_save, {'id': 'a', 'titel': 'x', 'beginn': '2026-10-06'}),
                      (server.api_termin_delete, {'id': 'a'})):
            try:
                r = fn(d)
            except RuntimeError:
                r = {'error': 'geworfen'}
            assert r.get('error'), (fn.__name__, r)
            assert open(server.TERMINE_JSON, encoding='utf-8').read() == kaputt, fn.__name__ + ' hat ueberschrieben'
        assert 'termine.json' in (server.api_kalender('2026-10-01', '2026-10-31')['error'] or '')
        os.remove(server.TERMINE_JSON)
        fehler = []
        def neu(i):
            r = server.api_termin_new({'titel': 'T%d' % i, 'beginn': '2026-10-%02d' % (i % 28 + 1)})
            if not r.get('ok'):
                fehler.append(r)
        th = [threading.Thread(target=neu, args=(i,)) for i in range(20)]
        [t.start() for t in th]
        [t.join() for t in th]
        assert not fehler, fehler
        assert len(server.termine_laden()) == 20, 'Termine beim parallelen Anlegen verloren'
    finally:
        if os.path.exists(server.TERMINE_JSON):
            os.remove(server.TERMINE_JSON)
        server.TERM.update(ts=0, evs=None, err='')


def test_termin_serien_und_fenster():
    """Monatlich/jaehrlich immer aus dem Original-Beginn; alte Serien laufen nicht in die
    1200er-Grenze; mehrtaegige Termine zaehlen bei Ueberlappung; Serien liefern ihre Originalwerte."""
    vor = server.termin_vorkommen
    r = vor({'beginn': '2026-01-31', 'wiederholung': 'monatlich'}, '2026-01-01', '2026-04-30')
    assert r == ['2026-01-31', '2026-02-28', '2026-03-31', '2026-04-30'], r
    r = vor({'beginn': '2024-02-29', 'wiederholung': 'jaehrlich'}, '2024-01-01', '2028-12-31')
    assert r == ['2024-02-29', '2025-02-28', '2026-02-28', '2027-02-28', '2028-02-29'], r
    r = vor({'beginn': '2026-01-31', 'wiederholung': 'frei', 'wdh_einheit': 'monate', 'wdh_intervall': 3},
            '2026-08-01', '2027-01-31')
    assert r == ['2026-10-31', '2027-01-31'], r
    r = vor({'beginn': '2020-01-01', 'wiederholung': 'taeglich'}, '2026-10-01', '2026-10-03')
    assert r == ['2026-10-01', '2026-10-02', '2026-10-03'], 'alte Tagesserie: %r' % r
    r = vor({'beginn': '2020-01-06', 'wiederholung': 'zweiwoechentlich'}, '2026-10-01', '2026-10-31')
    assert r == ['2026-10-05', '2026-10-19'], r
    open(server.TERMINE_JSON, 'w', encoding='utf-8').write(json.dumps([
        {'id': 'u', 'titel': 'Urlaub', 'beginn': '2026-08-01', 'ende': '2026-08-20', 'ganztags': True},
        {'id': 's', 'titel': 'Jour fixe', 'beginn': '2026-08-03T09:00', 'ende': '2026-08-03T10:00',
         'wiederholung': 'woechentlich'}]))
    server.TERM.update(ts=time.time() + 10 ** 6, evs=[], err='')
    try:
        ev = server.api_kalender('2026-08-10', '2026-08-15')['events']
        assert sorted(e['id'] for e in ev) == ['s', 'u'], 'Urlaub 1.-20. fehlt im Fenster 10.-15.: %r' % ev
        s = next(e for e in ev if e['id'] == 's')
        assert s['am'] == '2026-08-10 09:00' and s['serie_beginn'] == '2026-08-03T09:00' \
            and s['serie_ende'] == '2026-08-03T10:00', s
        assert 'u' not in [e['id'] for e in server.api_kalender('2026-08-21', '2026-08-23')['events']], \
            'Urlaub ragt ueber sein Ende hinaus'
    finally:
        os.remove(server.TERMINE_JSON)
        server.TERM.update(ts=0, evs=None, err='')


def test_local_events_eigenes_ende():
    """Jedes Vorkommen bekommt sein EIGENES Ende (Vorkommen-Tag + urspruengliche
    Dauer), nicht das Ende des ERSTEN Vorkommens -- das laege bei spaeteren Terminen vor dem
    Vorkommen-Tag, Woche und Mini-Monat wuerden sie verwerfen. serie_beginn/serie_ende bleiben
    unveraendert die Originalwerte der Serie (fuers Bearbeiten)."""
    open(server.TERMINE_JSON, 'w', encoding='utf-8').write(json.dumps([
        {'id': 'w', 'titel': 'Jour fixe', 'beginn': '2026-08-03T09:00', 'ende': '2026-08-03T10:00',
         'wiederholung': 'woechentlich'},
        {'id': 'k', 'titel': 'Konferenz', 'beginn': '2026-08-01', 'ende': '2026-08-03',
         'ganztags': True, 'wiederholung': 'jaehrlich'}]))
    server.TERM.update(ts=time.time() + 10 ** 6, evs=[], err='')
    try:
        ev = server.api_kalender('2026-08-01', '2027-12-31')['events']
        w2 = next(e for e in ev if e['id'] == 'w' and e['am'] == '2026-08-10 09:00')
        assert w2['ende'] == '2026-08-10T10:00', w2   # eigenes Ende, nicht das der Serie (03.08.)
        assert w2['serie_beginn'] == '2026-08-03T09:00' and w2['serie_ende'] == '2026-08-03T10:00', w2
        k2 = next(e for e in ev if e['id'] == 'k' and e['am'] == '2027-08-01')
        assert k2['ende'] == '2027-08-03', k2   # Dauer (2 Tage) auf das Vorkommen uebertragen
        assert k2['serie_beginn'] == '2026-08-01' and k2['serie_ende'] == '2026-08-03', k2
    finally:
        os.remove(server.TERMINE_JSON)
        server.TERM.update(ts=0, evs=None, err='')


def test_vorkommen_ende_ohne_uhrzeit_inklusiv():
    """Ein Ende OHNE Uhrzeit ist inklusiv, auch bei einem Termin MIT Uhrzeit --
    so schickt es das Formular, wenn die Endzeit leer bleibt (der .ics-Export wertet es ebenso). Der
    Server liefert dann je Vorkommen ebenfalls ein Ende ohne Uhrzeit (nur das Datum verschoben), nie
    'T00:00' (das waere exklusiv und liesse den letzten Tag in Woche/Mini-Monat verschwinden)."""
    open(server.TERMINE_JSON, 'w', encoding='utf-8').write(json.dumps([
        {'id': 'm', 'titel': 'Messe', 'beginn': '2026-08-11T09:00', 'ende': '2026-08-13'},
        {'id': 'se', 'titel': 'Seminar', 'beginn': '2026-08-03T09:00', 'ende': '2026-08-05',
         'wiederholung': 'woechentlich'}]))
    server.TERM.update(ts=time.time() + 10 ** 6, evs=[], err='')
    try:
        ev = server.api_kalender('2026-08-10', '2026-08-16')['events']
        m = next(e for e in ev if e['id'] == 'm')
        assert m['ende'] == '2026-08-13', m   # nicht '2026-08-13T00:00'
        s2 = next(e for e in ev if e['id'] == 'se' and e['am'] == '2026-08-10 09:00')
        assert s2['ende'] == '2026-08-12', s2   # 2 Tage Dauer auf das Vorkommen uebertragen, kein T00:00
    finally:
        os.remove(server.TERMINE_JSON)
        server.TERM.update(ts=0, evs=None, err='')


def test_termin_pruefe_ungueltige_zeit_abgewiesen():
    """DT_RE prueft nur das MUSTER (YYYY-MM-DD[THH:MM]), nicht den Wert -- '24:00' oder '2026-02-30'
    passen durch und liessen local_events() spaeter mit ValueError den ganzen Kalender kippen.
    termin_pruefe weist solche Werte jetzt schon beim Speichern ueber _dt_gueltig ab."""
    t, fehler = server.termin_pruefe({'titel': 'Spaet', 'beginn': '2026-08-11T22:00', 'ende': '2026-08-11T24:00'})
    assert t is None and 'Ende' in fehler['error'], (t, fehler)
    t, fehler = server.termin_pruefe({'titel': 'Schalttag', 'beginn': '2026-02-30'})
    assert t is None and 'Beginn' in fehler['error'], (t, fehler)
    t, fehler = server.termin_pruefe({'titel': 'Gueltig', 'beginn': '2026-08-11T22:00', 'ende': '2026-08-11T23:00'})
    assert t is not None and fehler is None, 'gueltiger Termin faelschlich abgewiesen: %r' % (fehler,)


def test_termin_pruefe_ende_gleicher_tag_ohne_uhrzeit():
    """Ein Ende OHNE Uhrzeit ist inklusiv, auch am selben Tag wie ein Beginn MIT
    Uhrzeit -- als Zeichenkette verglichen war '2026-08-11' < '2026-08-11T09:00' (kuerzerer String
    gilt als kleiner), termin_pruefe meldete faelschlich 'Ende liegt vor dem Beginn'. Genau das
    schickt terminWerte() in index.html, wenn Enddatum = Beginndatum und die Endzeit leer bleibt."""
    t, fehler = server.termin_pruefe({'titel': 'Messe', 'beginn': '2026-08-11T09:00', 'ende': '2026-08-11'})
    assert fehler is None and t['ende'] == '2026-08-11', (t, fehler)
    t, fehler = server.termin_pruefe({'titel': 'X', 'beginn': '2026-08-12T09:00', 'ende': '2026-08-11'})
    assert fehler and 'Ende' in fehler['error'], 'Ende vor dem Beginn-TAG muss weiter meckern: %r' % (fehler,)


def test_vorkommen_ende_altbestand_ungueltig_faellt_zurueck():
    """Eine von Hand editierte termine.json (oder eine aeltere, weniger strenge termin_pruefe-Fassung)
    kann eine ungueltige Zeit enthalten -- _vorkommen_ende darf local_events() dann nicht mit
    ValueError kippen (sonst bleiben auch Woche/Mini-Monat und die externen ICS-Termine leer),
    sondern faellt auf das gespeicherte Ende zurueck."""
    kaputt = {'beginn': '2026-08-11T22:00', 'ende': '2026-08-11T24:00'}
    assert server._vorkommen_ende(kaputt, '2026-08-11') == '2026-08-11T24:00'
    open(server.TERMINE_JSON, 'w', encoding='utf-8').write(json.dumps([
        dict(kaputt, id='x', titel='Spaet'),
        {'id': 'ok', 'titel': 'Normal', 'beginn': '2026-08-11T10:00', 'ende': '2026-08-11T11:00'}]))
    server.TERM.update(ts=time.time() + 10 ** 6, evs=[], err='')
    try:
        k = server.api_kalender('2026-08-10', '2026-08-16')   # darf nicht werfen
        assert sorted(e['id'] for e in k['events']) == ['ok', 'x'], k
    finally:
        os.remove(server.TERMINE_JSON)
        server.TERM.update(ts=0, evs=None, err='')


def test_termin_pruefe_wdh_bis_ungueltig_abgewiesen():
    """wdh_bis bekam bisher nur einen Muster-Check (Regex) und wurde bei kaputtem Wert einfach leer
    gelassen -- ein ueber die API direkt gesetztes '2026-02-30' kam durch und liess
    termin_vorkommen() spaeter beim Expandieren mit ValueError kippen. Jetzt wie beginn/ende per
    _dt_gueltig geprueft (das Formular kann den Wert nicht erzeugen, type=date)."""
    t, fehler = server.termin_pruefe({'titel': 'X', 'beginn': '2026-02-02T09:00',
                                      'wiederholung': 'woechentlich', 'wdh_bis': '2026-02-30'})
    assert t is None and 'Wiederholen' in fehler['error'], (t, fehler)
    t, fehler = server.termin_pruefe({'titel': 'X', 'beginn': '2026-02-02T09:00',
                                      'wiederholung': 'woechentlich', 'wdh_bis': '2026-02-20'})
    assert t is not None and t['wdh_bis'] == '2026-02-20', (t, fehler)


def test_local_events_ueberspringt_kaputten_altbestand():
    """Ein einzelner von Hand editierter Termin mit ungueltigem Kalenderdatum (im Ende oder in
    wdh_bis, z.B. '2026-02-30') darf local_events()/api_kalender() nicht mit ValueError kippen --
    Frueher war nur der Fall '24:00' abgefangen. Der kaputte Termin wird jetzt uebersprungen, die uebrigen
    (inklusive externer ICS-Termine, hier simuliert durch TERM) erscheinen weiter."""
    open(server.TERMINE_JSON, 'w', encoding='utf-8').write(json.dumps([
        {'id': 'schalt', 'titel': 'Schalttag', 'beginn': '2026-02-27', 'ende': '2026-02-30', 'ganztags': True},
        {'id': 'wdh', 'titel': 'Serie', 'beginn': '2026-02-02T09:00', 'ende': '2026-02-02T10:00',
         'wiederholung': 'woechentlich', 'wdh_bis': '2026-02-30'},
        {'id': 'ok', 'titel': 'Normal', 'beginn': '2026-02-27T09:00', 'ende': '2026-02-27T10:00'}]))
    server.TERM.update(ts=time.time() + 10 ** 6, evs=[], err='')
    try:
        k = server.api_kalender('2026-02-01', '2026-03-05')   # darf nicht werfen
        assert [e['id'] for e in k['events']] == ['ok'], k
    finally:
        os.remove(server.TERMINE_JSON)
        server.TERM.update(ts=0, evs=None, err='')


def test_termin_vorkommen_serie_vor_fenster():
    """Ein mehrtaegiges Serien-Vorkommen, das vor `von` beginnt und noch ins Fenster hineinreicht,
    fehlte bisher komplett -- bei Einzelterminen galt die Ueberlappung (dauer_tage) schon, bei der
    Wiederholung nicht. Gleiche Regel wie bei _im_fenster, jetzt auch beim Expandieren."""
    r = server.termin_vorkommen(
        {'beginn': '2026-08-01', 'ende': '2026-08-03', 'ganztags': True, 'wiederholung': 'jaehrlich'},
        '2026-08-03', '2026-08-09')
    assert '2026-08-01' in r, r   # Konferenz 01.-03.08.: Fenster beginnt erst am 03.08., Vorkommen reicht hinein
    r = server.termin_vorkommen(
        {'beginn': '2026-08-02T22:00', 'ende': '2026-08-03T02:00', 'wiederholung': 'taeglich'},
        '2026-08-03', '2026-08-03')
    assert r == ['2026-08-02', '2026-08-03'], r   # Nachtdienst 22-02 Uhr reicht ueber Mitternacht ins Fenster


def test_termin_vorkommen_serie_bis_ueberlappt_fenster():
    """Hat die Serie selbst ein 'Wiederholen bis', griff der fruehe Abbruch `von_d > grenze` schon,
    BEVOR die Dauer des mehrtaegigen Vorkommens abgezogen wurde -- das letzte Vorkommen fehlte dann,
    obwohl es noch ins Fenster hineinreicht (ein gleich langer Einzeltermin wurde schon immer
    geliefert). Jetzt wird erst gegen grenze + dauer_tage abgebrochen."""
    r = server.termin_vorkommen(
        {'beginn': '2026-07-24T18:00', 'ende': '2026-07-27T06:00', 'wiederholung': 'woechentlich',
         'wdh_bis': '2026-08-07'}, '2026-08-10', '2026-08-16')
    assert r == ['2026-08-07'], r   # WE-Dienst Fr 07.08. 18:00 bis Mo 10.08. 06:00 reicht in die Fensterwoche


def test_ueberlappung_ende_mitternacht_exklusiv():
    """Ueberlappung: Ein Ende MIT Uhrzeit 00:00 gehoert nicht mehr zum Vorkommen-Tag (exklusiv),
    ein Ende OHNE Uhrzeit bleibt inklusiv. Ohne diese Unterscheidung lieferte termin_vorkommen bei
    einer taeglichen Serie, die um Mitternacht endet, zusaetzlich das schon beendete Vortags-
    Vorkommen -- im Termine-Widget (api_termine/_im_fenster, kein evTag-Filter wie Woche/Mini-Monat)
    stand das dann faelschlich als heute noch laufend ganz oben (Nebenwirkung der Serien-Ueberlappung)."""
    assert server._letzter_kalendertag('2026-10-02T00:00') == '2026-10-01'
    assert server._letzter_kalendertag('2026-10-02T00:30') == '2026-10-02'
    assert server._letzter_kalendertag('2026-10-02') == '2026-10-02'
    r = server.termin_vorkommen({'beginn': '2026-10-01T18:00', 'ende': '2026-10-02T00:00',
                                 'wiederholung': 'taeglich'}, '2026-10-02', '2026-10-02')
    assert r == ['2026-10-02'], r   # nicht zusaetzlich '2026-10-01' (endete exklusiv VOR dem Fenster)
    e = {'am': '2026-10-01 18:00', 'ende': '2026-10-02T00:00'}
    assert not server._im_fenster(e, '2026-10-02', '2026-10-09'), e
    e2 = {'am': '2026-10-01', 'ende': '2026-10-02'}   # Ende OHNE Uhrzeit bleibt inklusiv
    assert server._im_fenster(e2, '2026-10-02', '2026-10-09'), e2


def test_ics_utc():
    """DTSTART mit Z ist UTC und wird in Ortszeit gezeigt; TZID=... bleibt wie geschrieben."""
    import calendar
    ev = server._ics_parse('BEGIN:VEVENT\nDTSTART:20260807T223000Z\nSUMMARY:x\nEND:VEVENT', 'K', '#000')[0]
    soll = time.strftime('%Y-%m-%d %H:%M', time.localtime(calendar.timegm((2026, 8, 7, 22, 30, 0, 0, 0, 0))))
    assert ev['am'] == soll, (ev['am'], soll)
    if time.strftime('%z', time.localtime(calendar.timegm((2026, 8, 7, 12, 0, 0, 0, 0, 0)))) == '+0200':
        assert ev['am'] == '2026-08-08 00:30', 'Sommerzeit Berlin: %s' % ev['am']
    ev = server._ics_parse('BEGIN:VEVENT\nDTSTART;TZID=Europe/Berlin:20260807T090000\nSUMMARY:x\nEND:VEVENT',
                           'K', '#000')[0]
    assert ev['am'] == '2026-08-07 09:00', ev['am']


def test_pfadpruefung_und_konflikt():
    """api_task_save prueft die Zone am AUFGELOESTEN Pfad; vault_md laesst keinen Nachbarordner
    mit gleichem Praefix zu; api_file liefert mtime_ns (String) und gekuerzt; api_task_save
    schreibt nur beim passenden mtime_ns."""
    echt = server.VAULT
    wurzel = tempfile.mkdtemp(prefix='puox-test-pfad-')
    server.VAULT = os.path.join(wurzel, 'vault')
    try:
        os.makedirs(os.path.join(server.VAULT, '09_aufgaben'))
        os.makedirs(os.path.join(wurzel, 'vault-alt'))
        open(os.path.join(server.VAULT, 'CLAUDE.md'), 'w').write('regeln')
        open(os.path.join(wurzel, 'vault-alt', 'x.md'), 'w').write('fremd')
        r = server.api_task_save({'path': '09_aufgaben/../CLAUDE.md', 'text': 'boese'})
        assert r.get('error') and open(os.path.join(server.VAULT, 'CLAUDE.md')).read() == 'regeln', r
        assert server.vault_md('../vault-alt/x.md') is None, 'Nachbarordner gilt als Vault'
        assert server.api_file('../vault-alt/x.md').get('error')
        p = os.path.join(server.VAULT, '09_aufgaben', 'a.md')
        open(p, 'w').write('x' * 150000)
        f = server.api_file('09_aufgaben/a.md')
        assert len(f['text']) == 150000 and f['gekuerzt'] is False, 'still gekuerzt'
        assert f['mtime_ns'] == str(os.stat(p).st_mtime_ns), f['mtime_ns']
        for falsch in (str(int(f['mtime_ns']) - 10 ** 9), int(float(f['mtime_ns'])) + 1, 'quatsch', [1]):
            r = server.api_task_save({'path': '09_aufgaben/a.md', 'text': 'neu', 'mtime_ns': falsch})
            assert r.get('error') and len(open(p).read()) == 150000, (falsch, r)
        r = server.api_task_save({'path': '09_aufgaben/a.md', 'text': 'neu', 'mtime_ns': f['mtime_ns']})
        assert r.get('ok') and r['mtime_ns'] == str(os.stat(p).st_mtime_ns) and open(p).read() == 'neu', r
        r = server.api_task_save({'path': '09_aufgaben/a.md', 'text': 'neu2', 'mtime_ns': int(r['mtime_ns'])})
        assert r.get('ok'), 'Ganzzahl muss ebenfalls gehen: %r' % r
        open(p, 'w').write('y' * (server.DATEI_MAX + 1))
        f = server.api_file('09_aufgaben/a.md')
        assert f['gekuerzt'] is True and len(f['text']) == server.DATEI_MAX
    finally:
        server.VAULT = echt


def test_pin_bremse_race_frei():
    """Parallele Fehlversuche einer IP: hoechstens ZUGANG_MAX werden ueberhaupt geprueft (frueher
    alle, weil jeder denselben Zaehlerstand sah). Dieselbe Bremse gilt fuer Mail-PIN und alte PIN."""
    import base64
    server.ZUGANG_VERSUCHE.clear()
    echt = server.zugang_data
    server.zugang_data = lambda: {'salt': base64.b64encode(b'x' * 16).decode('ascii'), 'hash': 'passt-nie'}
    geprueft = []
    def versuch():
        if server.api_zugang_anmelden({'pin': 'falsch1'}, '192.0.2.9').get('error') == 'PIN stimmt nicht':
            geprueft.append(1)
    try:
        th = [threading.Thread(target=versuch) for _ in range(30)]
        [t.start() for t in th]
        [t.join() for t in th]
    finally:
        server.zugang_data = echt
        server.ZUGANG_VERSUCHE.clear()
    assert len(geprueft) <= server.ZUGANG_MAX, '%d von 30 parallelen Versuchen geprueft' % len(geprueft)
    # Mail-PIN: eigener Zaehler je IP, richtige PIN setzt ihn zurueck
    salt = b'm' * 16
    open(server.MAIL_FILE, 'w', encoding='utf-8').write(json.dumps(
        {'pin_salt': salt.hex(), 'pin_hash': server._pin_hash('richtig1', salt), 'accounts': []}))
    tok = _zugang_pin()
    try:
        assert server.api_mail_unlock({'pin': 'richtig1'}, '192.0.2.10').get('token')
        for _ in range(server.ZUGANG_MAX):
            assert server.api_mail_unlock({'pin': 'falsch1'}, '192.0.2.10').get('error') == 'Falsche PIN'
        assert 'Fehlversuche' in server.api_mail_unlock({'pin': 'richtig1'}, '192.0.2.10')['error']
        assert server.api_mail_unlock({'pin': 'richtig1'}, '192.0.2.11').get('token'), 'andere IP gesperrt'
        # alte PIN beim Aendern: derselbe Zaehler wie die Anmeldung
        for _ in range(server.ZUGANG_MAX):
            r = server.api_zugang_aendern({'token': tok, 'alt': 'falsch1', 'neu': 'neupin1'}, '192.0.2.12')
            assert r.get('error') == 'Bisherige PIN stimmt nicht', r
        r = server.api_zugang_aendern({'token': tok, 'alt': '1234abcd', 'neu': 'neupin1'}, '192.0.2.12')
        assert 'Fehlversuche' in r.get('error', ''), r
        assert 'Fehlversuche' in server.api_zugang_anmelden({'pin': '1234abcd'}, '192.0.2.12').get('error', '')
    finally:
        server.ZUGANG_VERSUCHE.clear()
        os.remove(server.MAIL_FILE)
        os.remove(server.ZUGANG_FILE)
        server.zugang_abmelden(tok)


def test_origin():
    """CSRF: POST mit fremdem Origin -> 403, ohne Origin oder mit der eigenen Adresse -> durch."""
    eigen = 'https://%s' % server.NAME + ('' if server.PORT == 443 else ':%d' % server.PORT)
    assert server.origin_ok(None) and server.origin_ok('') and server.origin_ok(eigen)
    assert server.origin_ok(eigen.upper()), 'Schema/Host sind case-insensitiv'
    for fremd in ('https://boese.example.com', 'http://%s' % server.NAME, 'null', eigen + '.boese.tld',
                  'https://%s:8443' % server.NAME if server.PORT == 443 else 'https://%s' % server.NAME):
        assert not server.origin_ok(fremd), fremd
    tok = _zugang_pin()
    try:
        r = _anfrage('POST', '/api/termin/delete', {'Origin': 'https://boese.example.com', 'Cookie': 'puox_zugang=' + tok},
                     b'{"id": "nix"}')
        assert r.get('code') == 403, r
        r = _anfrage('POST', '/api/termin/delete', {'Origin': eigen, 'Cookie': 'puox_zugang=' + tok},
                     b'{"id": "nix"}')
        assert r.get('code') == 200 and b'nicht gefunden' in r['data'], r
    finally:
        os.remove(server.ZUGANG_FILE)
        server.zugang_abmelden(tok)


def test_zugang_fail_closed():
    """Existiert zugang.json, ist aber kaputt: KEIN Einrichtungsmodus, keine neue PIN, Anmelden
    meldet den Fehler statt durchzulassen."""
    for kaputt in ('{kaputt', '', '{}', '[]'):
        open(server.ZUGANG_FILE, 'w', encoding='utf-8').write(kaputt)
        try:
            assert server.zugang_eingerichtet(), 'kaputte Datei gilt als nicht eingerichtet: %r' % kaputt
            assert server.api_zugang_einrichten({'pin': 'neu12345'}).get('error'), kaputt
            assert open(server.ZUGANG_FILE, encoding='utf-8').read() == kaputt, 'neue PIN geschrieben'
            try:
                r = server.api_zugang_anmelden({'pin': 'neu12345'}, '192.0.2.20')
            except RuntimeError:
                r = {'error': 'geworfen'}
            assert r.get('error') and not r.get('token'), r
            assert _anfrage('GET', '/').get('code') == 401, 'Seite ohne Anmeldung ausgeliefert'
        finally:
            os.remove(server.ZUGANG_FILE)
            server.ZUGANG_VERSUCHE.clear()


def test_tls_stummer_client():
    """Ein TCP-Client, der nach dem Verbinden schweigt, darf weitere Anfragen nicht blockieren --
    der TLS-Handshake laeuft im Handler-Thread (mit H.timeout), nicht im Annahme-Thread."""
    import http.client
    import socket
    import ssl as _ssl
    if not (os.path.exists(server.TLS_CERT) and os.path.exists(server.TLS_KEY)):
        print('       (test_tls_stummer_client uebersprungen: kein Zertifikat)')
        return
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    erzeugt = []
    class Merk(server.ThreadingHTTPServer):         # nur um den Test-Server danach zu schliessen
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            erzeugt.append(self)
    echt, echt_netz = server.ThreadingHTTPServer, server.netz_cfg
    server.ThreadingHTTPServer = Merk
    try:
        assert server.binde(['127.0.0.1'], port, server.H, tls=True) == ['127.0.0.1']
    finally:
        server.ThreadingHTTPServer = echt
    server.netz_cfg = lambda: {'modus': 'lan', 'erlaubt': []}
    stumm = socket.create_connection(('127.0.0.1', port))
    try:
        time.sleep(0.2)
        c = http.client.HTTPSConnection('127.0.0.1', port, timeout=3, context=_ssl._create_unverified_context())
        try:
            c.request('GET', '/api/zugang/status', headers={'Host': server.NAME})
            code = c.getresponse().status
        except OSError as e:
            code = 'blockiert (%s)' % e
        c.close()
        assert code == 200, 'zweite Anfrage hinter stummem Client: %s' % code
    finally:
        server.netz_cfg = echt_netz
        stumm.close()
        for srv in erzeugt:
            srv.shutdown()
            srv.server_close()


def test_kalender_opn_fail_closed():
    """Unlesbare kalender.json/opnsense.json gelten nicht als leer -- sonst ueberschriebe das naechste
    Speichern alle Zugaenge. Lokale Termine bleiben trotzdem sichtbar."""
    for datei in (server.KAL_FILE, server.OPN_FILE):
        with open(datei, 'w', encoding='utf-8') as fh:
            fh.write('{kaputt')
    server.TERM.update(ts=0, evs=None)
    try:
        for fn in (server.kal_liste, server.opn_data):
            try:
                fn()
                assert False, '%s muss bei kaputter Datei werfen' % fn.__name__
            except RuntimeError:
                pass
        evs, err = server.ics_events()
        assert evs == [] and 'unlesbar' in err, (evs, err)
        for fn, d in ((server.api_kalender_setup, {'url': 'https://x.test/k.ics', 'name': 'Neu'}),
                      (server.api_opnsense_setup, {'url': 'https://x.test', 'key': 'k', 'secret': 's'})):
            try:
                r = fn(d)
            except RuntimeError:
                r = {'error': 'geworfen'}
            assert r.get('error'), (fn.__name__, r)
        for datei in (server.KAL_FILE, server.OPN_FILE):
            assert open(datei, encoding='utf-8').read() == '{kaputt', 'Datei ueberschrieben: %s' % datei
    finally:
        for datei in (server.KAL_FILE, server.OPN_FILE):
            os.remove(datei)
        server.TERM.update(ts=0, evs=None)


def test_out_stueckschreiben():
    """out() schreibt den Rumpf in Stuecken -- sonst gilt H.timeout fuer die GESAMTE Uebertragung
    (ein einziger wfile.write mit dem ganzen Rumpf), nicht je Schreibzugriff, und ein langsamer,
    aber staendig lesender Client wird bei grossen Antworten (Hintergrund, Mail-Anhang) nach
    30 s mitten im Rumpf abgebrochen."""
    class FakeWfile:
        def __init__(self):
            self.calls = []
        def write(self, chunk):
            self.calls.append(bytes(chunk))
    def _stub():
        h = server.H.__new__(server.H)
        h.send_response = lambda *a, **k: None
        h.send_header = lambda *a, **k: None
        h.end_headers = lambda: None
        h.wfile = FakeWfile()
        return h
    gross = _stub()
    data = os.urandom(server.SCHREIB_STUECK * 2 + 10)
    server.H.out(gross, data, 'application/octet-stream')
    assert len(gross.wfile.calls) == 3, 'kein Stueckschreiben: %d Aufrufe' % len(gross.wfile.calls)
    assert all(len(c) <= server.SCHREIB_STUECK for c in gross.wfile.calls)
    assert b''.join(gross.wfile.calls) == data, 'Rumpf beim Stueckeln veraendert'
    klein = _stub()
    server.H.out(klein, b'{"ok": true}', 'application/json')
    assert len(klein.wfile.calls) == 1, 'kleine Antwort unnoetig gestueckelt'


def test_handle_error_still():
    """Ein fehlgeschlagener TLS-Handshake (Klartext-HTTP auf dem TLS-Port) darf keinen Traceback
    ins Log schreiben -- seit do_handshake_on_connect=False laeuft der Handshake im Handler-Thread,
    und ein blankes ssl.SSLError landete dort sonst unveraendert in socketserver.handle_error."""
    import socket, io
    if not (os.path.exists(server.TLS_CERT) and os.path.exists(server.TLS_KEY)):
        print('       (test_handle_error_still uebersprungen: kein Zertifikat)')
        return
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    erzeugt = []
    class Merk(server.ThreadingHTTPServer):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            erzeugt.append(self)
    echt = server.ThreadingHTTPServer
    server.ThreadingHTTPServer = Merk
    try:
        assert server.binde(['127.0.0.1'], port, server.H, tls=True) == ['127.0.0.1']
    finally:
        server.ThreadingHTTPServer = echt
    alt_stderr = sys.stderr
    sys.stderr = io.StringIO()
    try:
        c = socket.create_connection(('127.0.0.1', port), timeout=2)
        c.sendall(b'GET / HTTP/1.0\r\n\r\n')   # Klartext auf dem TLS-Port -> ssl.SSLError beim Handshake
        time.sleep(0.3)
        c.close()
        ausgabe = sys.stderr.getvalue()
    finally:
        sys.stderr = alt_stderr
        for srv in erzeugt:
            srv.shutdown()
            srv.server_close()
    assert 'Traceback' not in ausgabe, 'SSLError beim Handshake schreibt einen Traceback: %r' % ausgabe[:300]


def test_ics_ungueltiges_datum():
    """Ein UTC-Termin vor 1970 (time.localtime wirft unter Windows) oder mit kalendarisch
    unmoeglichem Datum (30. Februar, strptime wirft) darf nicht den GANZEN Kalender kippen --
    der Termin behaelt seinen Rohwert, die anderen Termine derselben Quelle bleiben erhalten."""
    import calendar
    raw = ('BEGIN:VEVENT\nDTSTART:19690101T220000Z\nSUMMARY:Alter Jahrestag\nEND:VEVENT\n'
           'BEGIN:VEVENT\nDTSTART:20260230T100000Z\nSUMMARY:Unmoegliches Datum\nEND:VEVENT\n'
           'BEGIN:VEVENT\nDTSTART:20260807T223000Z\nSUMMARY:Normaler Termin\nEND:VEVENT')
    evs = server._ics_parse(raw, 'Test', '#000000')
    assert [e['was'] for e in evs] == ['Alter Jahrestag', 'Unmoegliches Datum', 'Normaler Termin'], evs
    assert evs[0]['am'] == '1969-01-01 22:00', evs[0]   # Rohwert behalten statt mit OSError zu werfen
    assert evs[1]['am'] == '2026-02-30 10:00', evs[1]   # Rohwert behalten statt mit ValueError zu werfen
    soll = time.strftime('%Y-%m-%d %H:%M', time.localtime(calendar.timegm((2026, 8, 7, 22, 30, 0, 0, 0, 0))))
    assert evs[2]['am'] == soll, (evs[2]['am'], soll)   # gueltige Termine werden weiter umgerechnet


def test_dek_unbekannter_codec():
    """Codecs wie 'undefined' oder 'idna' werfen auch mit errors='replace' noch UnicodeError statt
    LookupError -- sonst kippt eine einzelne Mail mit kaputtem Zeichensatz die ganze Ordnerliste
    bzw. bricht die Autoresponder-Schleife des Kontos ab."""
    for zs in ('undefined', 'idna', 'wirklich-unbekannt', None):
        assert server._dek(b'Hallo', zs) == 'Hallo', zs
    assert server._decode_hdr('=?undefined?q?Hallo?=') == 'Hallo'


def test_dek_nul_byte_zeichensatz():
    """Ein Zeichensatzname mit eingebettetem NUL-Byte wirft beim Decodieren ValueError
    ('embedded null character') -- keine Unterklasse von UnicodeError, darum von _dek vorher nicht
    abgefangen. Selten (IMAP-Literale duerfen laut RFC 3501 kein NUL enthalten), aber nicht jeder
    Server haelt das ein."""
    assert server._dek(b'Hallo', 'a\x00b') == 'Hallo'


def test_mail_anhang_rfc2231_zeichensatz():
    """filename*=undefined''... wirft in email.utils.collapse_rfc2231_value ein UnicodeError (RFC-
    2231-Zeichensatz 'undefined'/'idna'), das part.get_filename() ungefangen durchlaesst --
    _dateiname() faengt es jetzt ab (von _mail_parts UND mail_attachment_bytes genutzt), statt das
    Oeffnen der Nachricht bzw. den Anhang-Download zu kippen."""
    import email as email_lib
    raw = (b"From: a@b.de\r\nTo: c@d.de\r\nSubject: Test\r\n"
           b"Content-Type: multipart/mixed; boundary=X\r\n\r\n"
           b"--X\r\nContent-Type: text/plain\r\n\r\nHallo\r\n"
           b"--X\r\nContent-Type: application/pdf\r\n"
           b"Content-Disposition: attachment; filename*=undefined''Rechnung.pdf\r\n\r\n"
           b"%PDF-1.4\r\n--X--\r\n")
    msg = email_lib.message_from_bytes(raw)
    pdf_part = list(msg.walk())[2]
    assert server._dateiname(pdf_part) is False   # faengt ab statt zu werfen (Name war angegeben, nur kaputt)
    text_body, html_body, attachments = server._mail_parts(msg)
    assert text_body == 'Hallo', text_body
    assert attachments == [{'idx': 2, 'filename': 'anhang-2', 'size': 8, 'type': 'application/pdf'}], attachments


def test_mail_inline_anhang_kaputter_name():
    """Ein inline gesendeter Teil (z.B. ein eingebettetes PDF) mit kaputtem RFC-2231-Namen bekam
    bisher KEINEN Ersatznamen und verschwand komplett aus der Anhangsliste -- anders als bei
    'attachment', wo 'anhang-%d' schon griff. 'inline' zaehlt jetzt genauso."""
    import email as email_lib
    raw = (b"From: a@b.de\r\nTo: c@d.de\r\nSubject: Test\r\n"
           b"Content-Type: multipart/mixed; boundary=X\r\n\r\n"
           b"--X\r\nContent-Type: text/plain\r\n\r\nHallo\r\n"
           b"--X\r\nContent-Type: application/pdf\r\n"
           b"Content-Disposition: inline; filename*=undefined''Rechnung.pdf\r\n\r\n"
           b"%PDF-1.4\r\n--X--\r\n")
    msg = email_lib.message_from_bytes(raw)
    text_body, html_body, attachments = server._mail_parts(msg)
    assert text_body == 'Hallo', text_body
    assert attachments == [{'idx': 2, 'filename': 'anhang-2', 'size': 8, 'type': 'application/pdf'}], attachments


def test_mail_inline_ohne_namen_kein_anhang():
    """Die Ersatzname-Bedingung griff bisher bei JEDEM namenlosen inline-Teil, der kein
    Text ist -- ein eingebettetes cid-Logo OHNE Dateinamen (normal bei multipart/related) landete
    dadurch faelschlich als 'anhang-N' in der Liste. Der Ersatzname gilt jetzt nur noch, wenn ein
    Dateiname angegeben war und sich nicht decodieren liess (_dateiname() liefert dann False, nicht
    None); ein schlicht fehlender Name bleibt wie zuvor unsichtbar."""
    import email as email_lib
    raw = (b"From: a@b.de\r\nTo: c@d.de\r\nSubject: Test\r\n"
           b"Content-Type: multipart/related; boundary=X\r\n\r\n"
           b"--X\r\nContent-Type: text/html\r\n\r\n<img src=cid:logo>\r\n"
           b"--X\r\nContent-Type: image/png\r\n"
           b"Content-Disposition: inline\r\nContent-ID: <logo>\r\n\r\n\x89PNG\r\n--X--\r\n")
    msg = email_lib.message_from_bytes(raw)
    text_body, html_body, attachments = server._mail_parts(msg)
    assert html_body == '<img src=cid:logo>', html_body
    assert attachments == [], attachments   # kein Name angegeben -> kein Ersatzname, kein Anhang


def test_mail_charset_nul_byte_rfc2231():
    """Die RFC-2231-Form des charset-Parameters (charset*=...) mit eingebettetem NUL-Byte wirft schon
    in part.get_content_charset() ein ValueError ('embedded null character'), bevor _dek() ueberhaupt
    laeuft -- _content_charset() faengt das jetzt ab, genau wie _dateiname() beim Dateinamen."""
    import email as email_lib
    raw = b"Content-Type: text/plain; charset*=a\x00b''utf-8\r\nMIME-Version: 1.0\r\n\r\nHallo"
    msg = email_lib.message_from_bytes(raw)
    assert server._content_charset(msg) is None   # faengt ab statt zu werfen
    text_body, _, _ = server._mail_parts(msg)
    assert text_body == 'Hallo', text_body


def test_mail_parse_boundary_kaputt_nicht_lesbar():
    """Ein Kopf mit 'boundary*=undefined''X' (RFC-2231-Parameter mit Zeichensatz 'undefined') wirft
    schon in email.message_from_bytes() ein UnicodeError (get_boundary() -> collapse_rfc2231_value,
    faengt nur LookupError ab) -- eine Ebene vor _dateiname()/_content_charset(). _mail_parse()
    faengt das jetzt ab: die Mail gilt als nicht lesbar (None), statt die Nachrichtenliste/-ansicht
    oder den Autoresponder-Durchlauf des Kontos zu kippen."""
    import email as email_lib
    raw = b"From: a@b.de\r\nContent-Type: multipart/mixed; boundary*=undefined''X\r\n\r\n--X--\r\n"
    kaputt = False
    try:
        email_lib.message_from_bytes(raw)
    except (LookupError, ValueError):
        kaputt = True
    assert kaputt, 'Testkopf muesste ungeschuetzt werfen -- sonst testet dies nichts'
    assert server._mail_parse(raw) is None


def test_usage_tokens_letzte_zeile():
    """Eine Antwort schreibt je Inhaltsblock eine Zeile mit derselben Id -- fruehe Zeilen tragen nur
    einen Streaming-Zwischenstand von output_tokens, erst die letzte Zeile den Endwert. Gezaehlt
    werden muss das Maximum je Id, nicht blind die zuerst gelesene Zeile."""
    tmp = tempfile.mkdtemp(prefix='puox-test-home-')
    proj = os.path.join(tmp, '.claude', 'projects', 'p1')
    os.makedirs(proj)
    with open(os.path.join(proj, 'a.jsonl'), 'w', encoding='utf-8') as fh:
        for out in (8, 8, 250):   # Streaming-Zwischenstaende zuerst, Endwert zuletzt -- wie im echten Protokoll
            fh.write(json.dumps({'id': 'msg_x', 'input_tokens': 2, 'output_tokens': out,
                                 'cache_creation_input_tokens': 0}, separators=(',', ':')) + '\n')
    echt = os.path.expanduser
    os.path.expanduser = lambda p: tmp if p == '~' else echt(p)
    server.USG.clear()
    try:
        assert server.usage_tokens('all') == 2 + 250 + 0, 'nimmt nicht das Maximum je Id'
    finally:
        os.path.expanduser = echt
        server.USG.clear()


def test_usage_tokens_ohne_doppelzaehlung_subagent():
    """Ein Agent-Aufruf im Haupt-Thread speichert die usage der LETZTEN Subagenten-Nachricht noch
    einmal in einer eigenen toolUseResult-Zeile OHNE Id -- die zaehlt schon ueber die echte
    Subagenten-Datei (subagents/*.jsonl); die toolUseResult-Zeile darf nicht nochmal zaehlen."""
    tmp = tempfile.mkdtemp(prefix='puox-test-home2-')
    proj = os.path.join(tmp, '.claude', 'projects', 'p1')
    sub = os.path.join(proj, 'subagents')
    os.makedirs(sub)
    with open(os.path.join(sub, 's.jsonl'), 'w', encoding='utf-8') as fh:
        fh.write(json.dumps({'id': 'msg_sub', 'input_tokens': 10, 'output_tokens': 500,
                             'cache_creation_input_tokens': 0}, separators=(',', ':')) + '\n')
    with open(os.path.join(proj, 'a.jsonl'), 'w', encoding='utf-8') as fh:
        fh.write(json.dumps({'type': 'user', 'toolUseResult': {'usage': {
            'input_tokens': 10, 'output_tokens': 500, 'cache_creation_input_tokens': 0}}},
            separators=(',', ':')) + '\n')
    echt = os.path.expanduser
    os.path.expanduser = lambda p: tmp if p == '~' else echt(p)
    server.USG.clear()
    try:
        assert server.usage_tokens('all') == 10 + 500 + 0, 'toolUseResult-Zeile zaehlt doppelt'
    finally:
        os.path.expanduser = echt
        server.USG.clear()


def test_usage_tokens_workflow_subagenten():
    """Workflow-Agenten schreiben eine Ebene tiefer als normale Subagenten: <sitzung>/subagents/
    workflows/<wf>/agent-*.jsonl. Der Glob muss auch
    diese Tiefe erfassen, sonst fehlt der groesste Teil der echten Usage."""
    tmp = tempfile.mkdtemp(prefix='puox-test-home3-')
    wf = os.path.join(tmp, '.claude', 'projects', 'p1', 'subagents', 'workflows', 'wf_x')
    os.makedirs(wf)
    with open(os.path.join(wf, 'agent-1.jsonl'), 'w', encoding='utf-8') as fh:
        fh.write(json.dumps({'id': 'msg_wf', 'input_tokens': 1, 'output_tokens': 999,
                             'cache_creation_input_tokens': 0}, separators=(',', ':')) + '\n')
    echt = os.path.expanduser
    os.path.expanduser = lambda p: tmp if p == '~' else echt(p)
    server.USG.clear()
    try:
        assert server.usage_tokens('all') == 1 + 999 + 0, 'Workflow-Subagenten-Datei nicht gezaehlt'
    finally:
        os.path.expanduser = echt
        server.USG.clear()


def test_mail_attachment_auth():
    """Ungueltiges oder abgelaufenes Mail-Token liefert am Anhang-Endpunkt 401 mit auth:True wie
    jeder andere Mail-Endpunkt -- vorher kam immer 404 ohne 'auth', egal ob das Token ungueltig war
    oder der Anhang fehlte, und die UI konnte den haeufigsten Fall (Neustart, Token weg) nicht von
    einem wirklich fehlenden Anhang unterscheiden."""
    tok = _zugang_pin()
    try:
        r = _anfrage('GET', '/api/mail/attachment?token=bad&account=x&folder=INBOX&uid=1&idx=0',
                     {'Cookie': 'puox_zugang=' + tok})
        assert r.get('code') == 401, r
        d = json.loads(r['data'])
        assert d.get('auth') is True and d.get('error'), d
    finally:
        os.remove(server.ZUGANG_FILE)
        server.zugang_abmelden(tok)


def test_pin_bremse_fenster_nach_ablauf():
    """Nach Ablauf der 15-Minuten-Sperre faengt die Zaehlung neu an -- sonst sperrt der naechste
    einzelne Fehlversuch (oder bei der stillen Pruefung schon die naechste Tipp-Pause) sofort
    wieder fuer 15 Minuten, und der Betreiber sperrt sich beim normalen Tippen selbst dauerhaft aus."""
    server.ZUGANG_VERSUCHE.clear()
    schluessel = 'test-fenster'
    try:
        for _ in range(server.ZUGANG_MAX):
            assert server.pin_bremse(schluessel) is None
        gesperrt = server.pin_bremse(schluessel)
        assert gesperrt and 'Fehlversuche' in gesperrt
        n, _sperre = server.ZUGANG_VERSUCHE[schluessel]
        server.ZUGANG_VERSUCHE[schluessel] = (n, time.time() - 1)   # Sperre ist gerade abgelaufen
        assert server.pin_bremse(schluessel) is None, 'Fenster nicht zurueckgesetzt -- sperrt sofort wieder'
        for _ in range(server.ZUGANG_MAX - 1):
            assert server.pin_bremse(schluessel) is None
        wieder = server.pin_bremse(schluessel)
        assert wieder and 'Fehlversuche' in wieder, 'nach ZUGANG_MAX Versuchen im neuen Fenster muss wieder gesperrt werden'
    finally:
        server.ZUGANG_VERSUCHE.clear()


def test_ganztags_ende_mitternacht_einheitlich():
    """Ganztags mit Ende 'T00:00' (Formular: Beginn ohne Uhrzeit, Endzeit 00:00): Woche ab dem Endtag und
    Mini-Monat muessen dasselbe liefern -- vorher zeigte der Monat den Endtag, die Woche nicht."""
    import json
    t, fehler = server.termin_pruefe({'titel': 'Urlaub', 'beginn': '2026-08-08', 'ende': '2026-08-10T00:00'})
    assert not fehler and t.get('ganztags'), (t, fehler)
    t['id'] = 'g1'
    with open(server.TERMINE_JSON, 'w', encoding='utf-8') as fh:
        json.dump([t], fh)
    try:
        woche = [(e['am'], e['ende']) for e in server.local_events('2026-08-10', '2026-08-16')]
        monat = [(e['am'], e['ende']) for e in server.local_events('2026-07-27', '2026-09-06')]
        assert woche == monat == [('2026-08-08', '2026-08-10')], (woche, monat)
    finally:
        os.remove(server.TERMINE_JSON)


if __name__ == '__main__':
    fehler = 0
    for name, fn in sorted(globals().items()):
        if name.startswith('test_') and callable(fn):
            try:
                fn()
                print('  ok   %s' % name)
            except AssertionError as e:
                fehler += 1
                print('  FAIL %s: %s' % (name, e))
    print('alles gruen' if not fehler else '%d Fehler' % fehler)
    sys.exit(1 if fehler else 0)
