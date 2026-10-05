'''PUOX-OS-Autostart: startet server.py nach der Anmeldung ohne Fenster und ohne Browser.

Aufruf: Verknuepfung PUOX-OS.lnk im Autostart-Ordner (shell:startup) -> pythonw.exe autostart.pyw.
Von Hand nur per Doppelklick auf PUOX-OS.lnk, nie per Start-Process aus einer Claude-Sitzung: der
Server erbte sonst deren Umgebung (CLAUDECODE, Sitzungs-Token) bis zur Abmeldung (gemessen 26.09.2026).
pythonw.exe startet nur und lauscht nie. Den Server betreibt python.exe mit CREATE_NO_WINDOW:
Konsole ohne Fenster, die auch git-/claude-Kindprozesse erben (gemessen 26.09.2026).
pythonw.exe als Server scheidet aus: Konsolen-Kinder bekaemen je ein eigenes Fenster, und fuer
pythonw.exe gibt es keine Firewall-Regel. Lauscht ein Programm ohne Regel zum ersten Mal, zeigt
Windows den Sicherheitshinweis und legt dabei SOFORT Blockregeln an (Firewall-Log 17.09.2026
16:36:50) - so fiel os.example.com aus. Deshalb ist PYTHON fest: die Regeln haengen an diesem Pfad.

Wartet hoechstens WARTEN s auf die Tunneladresse; gleiche Quelle wie NETZ_EIGENE() in server.py,
das die Adressen nur einmal beim Start liest. Laeuft PUOX-OS schon, endet autostart.pyw sofort, noch
bevor es das Log oeffnet: 'w' kuerzte sonst das Log, das der laufende Server als Ausgabe offen haelt
(Stand 02.10.2026).'''
import os, socket, subprocess, sys, time

TUNNEL = '10.8.0.3'   # WireGuard-Tunnel
WARTEN = 120             # s; danach Start ohne Tunnel (localhost + LAN), Hinweis im Log
BASE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(os.path.dirname(BASE), '_tools', 'skripte', 'puox-os-last.log')  # gitignored
PYTHON = os.path.join(os.environ['LOCALAPPDATA'], 'Programs', 'Python', 'Python312', 'python.exe')


def tunnel_da():
    try:
        infos = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
    except OSError:
        return False
    return any(i[4][0] == TUNNEL for i in infos)


def jetzt():
    return time.strftime('%Y-%m-%d %H:%M:%S')


try:
    sys.path.insert(0, BASE)
    import server   # nur fuer auf_port(): erkennt PUOX-OS am Server-Kopf, nicht nur am belegten Port
    if server.auf_port(server.PORT) == 'puox-os':
        sys.exit(0)
except Exception:
    pass   # Pruefung selbst kaputt -> normaler Start; server.py meldet seinen Fehler dann ins Log

try:
    log = open(LOG, 'w', encoding='utf-8')
except OSError:
    log = open(os.devnull, 'w')
with log:
    beginn = time.monotonic()
    da = tunnel_da()
    while not da and time.monotonic() - beginn < WARTEN:
        time.sleep(3)
        da = tunnel_da()
    print(jetzt(), 'Autostart: Tunnel', TUNNEL, 'da' if da else 'FEHLT - Start ohne Tunnel',
          'nach %d s' % (time.monotonic() - beginn), file=log, flush=True)
    # Bewusst schlicht: kein Wiederanlauf nach Absturz; Exitcode steht unten im Log, Neustart per Doppelklick auf PUOX-OS.lnk
    try:
        rc = subprocess.call([PYTHON, '-u', os.path.join(BASE, 'server.py'), '--nobrowser'],
                             cwd=BASE, stdin=subprocess.DEVNULL, stdout=log,
                             stderr=subprocess.STDOUT, creationflags=subprocess.CREATE_NO_WINDOW,
                             env=dict(os.environ, PYTHONIOENCODING='utf-8'))
    except OSError as e:
        rc = e
    print(jetzt(), 'server.py beendet:', rc, file=log)
