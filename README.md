# Raspberry MCP Gateway

> **Am 23.11.2026 als Source-only-Quellcode veröffentlicht – kein freigegebenes HAOS-Installations- oder Produktrelease.** Die veröffentlichte App-Quellfassung (`1.1.0`, experimentell) ist nicht unter HAOS abgenommen und nicht für einen ungeprüften produktiven Einsatz freigegeben.

Raspberry MCP Gateway ergänzt Home Assistant OS um einen lokalen MCP-Gateway-Prozess, der über **einen** OpenAI-Tunnel erreichbar ist. Die Anwendung verbindet die bewusst beschränkten Home-Assistant-MCP-Werkzeuge mit lokalen, standardmäßig lesenden Diagnose- und Vorschaufunktionen. Schreibfunktionen sind separat geschützt und standardmäßig deaktiviert.

## Umfang und Voraussetzungen

- Zielplattform laut App-Metadaten: `aarch64` / ARM64; Home Assistant OS und Add-on-/App-Supervisor.
- Der Quellcode enthält das Dockerfile, `apk-arm64.lock` und `requirements-arm64.lock`. **Es wird kein vorgebautes Container-Image angeboten.** Nutzer bauen selbst mit Docker/BuildKit; die Buildumgebung benötigt Zugriff auf die offiziellen OCI-Registries, Alpine Stable und PyPI.
- Das Image kopiert den Tunnel-Client aus einem gepinnten offiziellen OCI-Image; Python und Linux-Systempakete stammen aus den im Dockerfile festgelegten Quellen.
- Für den Betrieb sind ein korrekt eingerichteter Home-Assistant-MCP-Endpunkt, ein dafür berechtigtes Home-Assistant-Zugriffstoken und die gültigen Tunnel-Zugangsdaten erforderlich. Zugangsdaten niemals ins Repository oder in Supportprotokolle kopieren.
- Der Quellstand verwendet im Launcher nur die HA-MCP-Zieladressen `http://homeassistant.local:8123/api/mcp` oder `http://homeassistant:8123/api/mcp`. Bei abweichender Netzwerkkonfiguration kann der Start scheitern; keine beliebigen externen Zieladressen freischalten.

## ARM64-Image lokal bauen (Docker/BuildKit)

Aus dem Verzeichnis, das den Ordner `openai_mcp_tunnel/` enthält:

```sh
docker build --platform linux/arm64 \
  --tag raspberry-mcp-gateway:local-review \
  ./openai_mcp_tunnel
```

Der Befehl ist für einen ARM64-fähigen Docker-Builder vorgesehen und wurde als Dokumentationsbeispiel aus dem Dockerfile abgeleitet. **Das ist noch keine freigegebene Installationsanleitung für Home Assistant OS**. Er installiert oder startet die App nicht. Keine Zugangsdaten als Build-Argumente verwenden.

## Home Assistant OS: App-Konfiguration

Die enthaltene `openai_mcp_tunnel/config.yaml` legt das App-Schema fest. `stage: experimental` kennzeichnet diesen **nicht produktionsfreigegebenen Quellstand**; `slug: openai_mcp_tunnel` und die sicheren Laufzeitoptionen bleiben für die bestehenden Integrationen unverändert. Das öffentliche Quellcode-Repository ist bereits eingerichtet; in der enthaltenen App-Konfiguration ist noch keine projektbezogene `url` eingetragen:

| Option | Zweck / sichere Vorgabe |
| --- | --- |
| `CONTROL_PLANE_TUNNEL_ID` | Tunnelkennung; nur in der lokalen App-Konfiguration setzen |
| `CONTROL_PLANE_API_KEY` | Tunnel-Zugangsdaten; Geheimnis |
| `MCP_SERVER_URL` | Interner Home-Assistant-MCP-Endpunkt |
| `HA_ACCESS_TOKEN` | Berechtigtes HA-Token; Geheimnis |
| `MCP_WRITE_ENABLED` | **`false`**: Schreibzugriffe standardmäßig aus |
| `APPROVED_ACTION` | Leer; Einmalfreigabe nur im gesondert genehmigten Anwendungsfall |
| `BACKUP_RETENTION_MODE` | **`off`**; keine automatische Löschung |

Die App startet manuell (`boot: manual`); `apparmor: true` ist konfiguriert. Der Home-Assistant-Konfigurationsmount ist laut App-Metadaten technisch schreibbar; die tatsächlichen Schreibgrenzen müssen deshalb **durch das geladene AppArmor-Profil und die Anwendungsgates** erzwungen werden. Das ist im aktuellen Entwicklungsstand noch nicht vollständig in einem isolierten ARM64-HAOS-Labor nachgewiesen.

**Keine automatische Installation auf einem produktiven Home Assistant:** Ältere, privat betriebene Versionen des Gateways sind keine HAOS-Abnahme dieses veränderten Quellkandidaten. Der aktuelle Quellstand ist noch nicht auf HAOS integriert getestet. Die umfassende HAOS-/AppArmor-/Recovery-Abnahme ist **keine Voraussetzung für eine klar als ungetestet gekennzeichnete Source-only-Veröffentlichung**, wohl aber vor einer Installations-/Produktfreigabe. Diese Anleitung ersetzt sie nicht.

## Sicherheits- und Versionsstand

Die aktuelle Entwicklungsfassung hat in privater CI mit Python 3.15/FastMCP 4.2.4 **284 Offline-Tests** bestanden, darunter die Beschränkung des HA-Proxys auf drei Werkzeuge sowie Verweigerungs- und Reconnect-Tests. Das ist **kein** vollständiger HAOS-/AppArmor-Nachweis.

Im nativen ARM64-Scan zur v1.1.0 wurden **neun bekannte High-CVE-IDs** in SQLite/OpenSSL und keine Critical-CVEs gemeldet. Die neun High-Risiken sind einzeln bewertet; das aktualisierte CVE-Gate hat seine regulären Tests bestanden, aber für den veröffentlichten Stand liegt noch kein eigenständiger offizieller Gate-PASS vor. Die SLSA-v1-Herkunft des gepinnten offiziellen Tunnel-OCI-Image-Indexes ist inzwischen bestätigt. **Keine Sicherheits- oder Produktionsfreigabe** ableiten.

Siehe [Sicherheitsleitfaden](SECURITY.md) für Betrieb, Zugangsdaten, Freigaben, Grenzen und Wiederherstellung.



**Transparenz zum Sicherheitsstatus:** Der veröffentlichte Quellcode wird **ohne Hersteller-Image und ohne Zusage einer getesteten HAOS-Installation** angeboten. Die neun im ARM64-Scan dokumentierten High-CVEs sind in [SECURITY.md](SECURITY.md) einzeln aufgeführt; die installierten Bibliotheken werden durch die gepinnten Lockdateien nicht automatisch sicherer. Der Quellstand ist weder als CVE-frei noch als produktionsreif zu betrachten.

## Lizenz und Veröffentlichung

Apache-2.0 gilt ausschließlich für diejenigen Projekt-Quelldateien, deren Rechte diese Lizenzierung zulassen. Fremde Quellen und Abhängigkeiten behalten ihre eigenen Lizenzen. Im öffentlichen Repository dürfen nur im finalen Snapshot geprüfte Dateien und erforderliche Hinweise enthalten sein. Das private Entwicklungsrepository und seine Historie werden nicht automatisch veröffentlicht.
