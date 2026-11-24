# Changelog

Änderungen an der Home-Assistant-App **Raspberry MCP Gateway**.

## 1.1.2 – 24.11.2026

### Status und Release-Metadaten
- Die Home-Assistant-App wird für den dokumentierten und begrenzten Einsatzumfang von `experimental` auf `stable` eingestuft.
- Versions-, README- und Sicherheitsdokumentation an die neue Einstufung angepasst; AppArmor-Policy, Gateway-Code, Dockerfile, Paketversionen, Laufzeitoptionen und sichere Standardwerte bleiben unverändert.

### Bereits vorhandene Nachweise und Grenzen
- Historischer AppArmor-Kernel-Negativtest vom 18.11.2026 (`errno=13`) wird für seinen damaligen Umfang anerkannt. Die unveränderte Policy wird unter der derzeit installierten v1.1.1 durch eine lesende Diagnose mit passender Profilkennung und `enforce` ergänzt. Ein erneuter versionsspezifischer Kernel-DENIED-Test ist nicht erfolgt.
- Isolierte Raspberry-Recovery-Simulation am 24.11.2026: 17/17 Tests bestanden. Ein echter HAOS-Neustart oder vollständiger Disaster-Recovery-Test wurde nicht durchgeführt.
- Neun bekannte High-CVEs aus einem historisch geprüften ARM64-Build wurden einzeln und versionsgebunden als Restrisiko bewertet, nicht behoben. Eine erneute Container-Sicherheitsfreigabe für einen neuen Build wird nicht behauptet.
- Die `stable`-Einstufung ist keine Zertifizierung und keine pauschale Freigabe aller Schreib- und Recovery-Szenarien.

## 1.1.1 – 23.11.2026

### Behoben
- Die lesende AppArmor-Diagnose erkennt neben `local_openai_mcp_tunnel` auch das von Home Assistant verwendete Repository-Präfix mit achtstelliger Hex-Kennung.
- Die Profilprüfung vergleicht den vollständigen Profilnamen des MCP-Prozesses; fremde oder nur ähnlich benannte Profile werden nicht als bestätigt gewertet.

### Verifiziert
- Ergänzte Offline-Regressionstests für lokale und Repository-Profile sowie für abzulehnende Profilnamen.
- Private GitHub-CI einschließlich Syntax- und Regressionstests erfolgreich.

### Unverändert
- MCP-Tunnel, Anwendungsgates und sichere Laufzeitvorgaben; Schreibfunktionen bleiben standardmäßig deaktiviert.
- Die Bestätigung der tatsächlich geladenen AppArmor-Policy auf der aktualisierten HAOS-Installation steht noch aus.

## 1.1.0 – 23.11.2026

### Veröffentlicht
- Öffentlicher ARM64-Quellstand als Home-Assistant-App zum Selbstbau mit Docker/BuildKit; kein vorgebautes Container-Image.
- MCP-Tunnel zur Verbindung mit Home Assistant und bewusst eingeschränktem Upstream-MCP-Proxy.
- Lesende YAML- und Dashboard-Werkzeuge sowie separat geschützte Schreibfunktionen mit expliziten Freigaben, Vorschau und SHA256-Prüfungen.
- Gepinnte Python- und Alpine-Paketabhängigkeiten für den ARM64-Selbstbau.
- Sicherheitsdokumentation und Lizenzhinweise im öffentlichen Repository.

### Betrieb und Sicherheitsstand
- Die App wurde in einer privaten Home-Assistant-OS-Installation gestartet; Tunnel und lesende MCP-Funktionen wurden praktisch geprüft.
- Status `experimental`; keine allgemeine HAOS-Produktionsfreigabe oder vollständige AppArmor-/Recovery-Abnahme.
- Bekannte High-CVEs und verbleibende Nachweise sind in [SECURITY.md](../SECURITY.md) beschrieben.
