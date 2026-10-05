# PUOX-OS unter https://os.example.com erreichbar machen.
#
# EINMAL ALS ADMINISTRATOR AUSFUEHREN:
#   Rechtsklick auf die Datei -> "Mit PowerShell ausfuehren" (als Administrator)
#   oder:  powershell -ExecutionPolicy Bypass -File netz-einrichten.ps1
#
# Setzt zwei Dinge, fuer die Windows Administratorrechte verlangt:
#   1. Firewall-Regeln: Port 443 (und 80 fuer die Weiterleitung) eingehend,
#      AUSSCHLIESSLICH aus dem WireGuard-Netz 10.8.0.0/24
#   2. hosts-Eintrag auf DIESEM Rechner: 127.0.0.1 -> os.example.com
#
# HINTERGRUND:
#   - Erreichbar nur unter https://os.example.com. Der Server bedient
#     ausschliesslich diesen Namen; jede andere Adresse bekommt 421.
#   - Der Zugang laeuft nur noch ueber WireGuard. Die alte Regel liess
#     das ganze LAN-Subnetz durch - das tut sie jetzt NICHT mehr. Ein Geraet im eigenen
#     WLAN ohne Tunnel kommt nicht mehr durch, das ist so gewollt.
#   - Profil: die alte Regel galt nur Privat/Domaene. Eine WireGuard-Schnittstelle
#     ordnet Windows in aller Regel dem Profil "Oeffentlich" zu - mit der alten
#     Einschraenkung waere der Tunnel ausgesperrt gewesen. Deshalb gilt die Regel fuer
#     ALLE Profile, dafuer aber streng auf die Tunnel-Adressen begrenzt. Die Begrenzung
#     macht die Arbeit, nicht das Profil.
#
# Der hosts-Eintrag zeigt bewusst auf 127.0.0.1, nicht auf die Tunnel-IP: Steht der
# Tunnel einmal nicht, loest os.example.com sonst auf 10.8.0.3 auf, diese Adresse
# existiert dann nicht, und PUOX-OS waere auf dem eigenen Rechner nicht mehr erreichbar,
# obwohl es dort laeuft. Andere Geraete kommen unveraendert per DNS durch den Tunnel.

$ErrorActionPreference = 'Stop'

$NAME    = "os.example.com"
$TUNNEL  = "10.8.0.0/24"

function Ist-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Ist-Admin)) {
    Write-Host "Dieses Skript braucht Administratorrechte." -ForegroundColor Red
    Write-Host "Rechtsklick auf die Datei -> 'Als Administrator ausfuehren'."
    Read-Host "Mit Enter schliessen"
    exit 1
}

# --- Lagebericht: steht der Tunnel ueberhaupt? ---
$tunnelIp = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
             Where-Object { $_.IPAddress -like "10.8.0.*" } | Select-Object -First 1).IPAddress
if ($tunnelIp) {
    Write-Host "WireGuard-Adresse dieses Rechners: $tunnelIp" -ForegroundColor Cyan
} else {
    Write-Host "Hinweis: Derzeit keine Adresse aus $TUNNEL gefunden - der Tunnel steht gerade nicht." -ForegroundColor Yellow
    Write-Host "         Die Regeln werden trotzdem gesetzt; sie greifen, sobald er steht."
}

# --- 1. Firewall: 443 und 80 eingehend, nur aus dem Tunnelnetz ---
# Alte Regel aus einer frueheren Einrichtung entfernen, sonst bleibt Port 80 fuer das ganze
# LAN offen und die Umstellung auf "nur ueber VPN" waere nur die halbe Wahrheit.
$alt = "PUOX-OS (Port 80, nur LAN)"
$altRegel = Get-NetFirewallRule -DisplayName $alt -ErrorAction SilentlyContinue
if ($altRegel) {
    $altRegel | Remove-NetFirewallRule
    Write-Host "[OK] Alte LAN-Regel '$alt' entfernt" -ForegroundColor Green
} else {
    Write-Host "[--] Alte LAN-Regel '$alt' war nicht vorhanden" -ForegroundColor DarkGray
}

$regeln = @(
    @{ Name = "PUOX-OS (443, nur WireGuard)"; Port = 443; Zweck = "das Dashboard selbst" },
    @{ Name = "PUOX-OS (80, Weiterleitung, nur WireGuard)"; Port = 80; Zweck = "Weiterleitung http->https" }
)
foreach ($r in $regeln) {
    $vorhanden = Get-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue
    if ($vorhanden) { $vorhanden | Remove-NetFirewallRule }
    New-NetFirewallRule -DisplayName $r.Name -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort $r.Port -RemoteAddress $TUNNEL -Profile Any | Out-Null
    Write-Host ("[OK] Firewall: Port {0} eingehend, nur aus {1}  ({2})" -f $r.Port, $TUNNEL, $r.Zweck) -ForegroundColor Green
}
Write-Host "     Alle Profile, dafuer streng auf die Tunnel-Adressen begrenzt." -ForegroundColor DarkGray

# --- Gegenprobe: existieren die Regeln wirklich? ---
# Am 17.09.2026 meldete ein Lauf Erfolg, hinterliess aber KEINE einzige Regel - der
# Fehler fiel erst auf, als ein zweiter Rechner nicht durchkam. Deshalb wird hier
# nicht der Rueckgabewert geglaubt, sondern nachgesehen.
$fehlen = @()
foreach ($r in $regeln) {
    if (-not (Get-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue)) { $fehlen += $r.Name }
}
if ($fehlen.Count -gt 0) {
    Write-Host ""
    Write-Host "[FEHLER] Diese Regeln wurden NICHT angelegt:" -ForegroundColor Red
    $fehlen | ForEach-Object { Write-Host "          $_" -ForegroundColor Red }
    Write-Host "         Ohne sie kommt kein anderes Geraet durch. Skript als Administrator erneut ausfuehren." -ForegroundColor Red
    Read-Host "Mit Enter schliessen"
    exit 1
}
Write-Host "[OK] Gegenprobe: beide Regeln sind gesetzt und aktiv" -ForegroundColor Green

# --- 2. hosts-Eintrag auf diesem Rechner ---
$hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
$zeile = "127.0.0.1`t$NAME"
$inhalt = Get-Content $hosts -ErrorAction SilentlyContinue
# Fruehere PUOX-OS-Eintraege herausnehmen.
$ohneAlt = $inhalt | Where-Object {
    $_ -notmatch ('\s' + [regex]::Escape($NAME) + '\s*$') -and
    $_ -notmatch '^\s*#\s*PUOX-OS'
}
$neu = @($ohneAlt) + @("# PUOX-OS", $zeile)
Set-Content -Path $hosts -Value $neu -Encoding ASCII
Write-Host "[OK] hosts-Eintrag gesetzt: $zeile" -ForegroundColor Green
Write-Host "     (ersetzt fruehere PUOX-OS-Eintraege)" -ForegroundColor DarkGray

ipconfig /flushdns | Out-Null
Write-Host "[OK] DNS-Zwischenspeicher geleert" -ForegroundColor Green

Write-Host ""
Write-Host "Fertig. PUOX-OS ist erreichbar unter:" -ForegroundColor Cyan
Write-Host "   https://$NAME"
Write-Host ""
Write-Host "Auf diesem Rechner ueber die hosts-Zeile, auf jedem anderen Geraet ueber DNS," -ForegroundColor DarkGray
Write-Host "sobald der A-Record 'os' -> 10.8.0.3 beim DNS-Anbieter gesetzt ist - und nur mit"
Write-Host "aktivem WireGuard-Tunnel. Ohne Tunnel gar nicht."
Write-Host ""
Write-Host "NOCH OFFEN, nicht von diesem Skript erledigt:" -ForegroundColor Yellow
Write-Host "   - A-Record 'os' -> 10.8.0.3 beim DNS-Anbieter"
Write-Host "     Als DNS-Eintrag fuer example.com anlegen, NICHT unter"
Write-Host "     'Subdomains' im Hosting-Panel: das legt dort Webspace an, nicht was wir wollen."
Write-Host ""
Write-Host "Zertifikat: selbstsigniert, laeuft bis 2036." -ForegroundColor Cyan
Write-Host "Kein acme.sh, kein 90-Tage-Ritual. Jedes Geraet bestaetigt die Ausnahme EINMAL -"
Write-Host "danach ist Ruhe. Verschluesselt ist das genauso stark wie Let's Encrypt; der"
Write-Host "Browser kennt nur den Aussteller nicht und sagt das in der Adressleiste."
Write-Host ""
Write-Host "Systemuhr pruefen: lag sie falsch, scheitert die TLS-Pruefung mit irrefuehrender Meldung." -ForegroundColor Yellow
Write-Host ("   jetzt: {0}" -f (Get-Date))
Write-Host ""
Read-Host "Mit Enter schliessen"
