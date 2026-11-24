# Changelog

Änderungen an der Home-Assistant-App **Raspberry MCP Gateway**.

## 1.1.2 – 24.11.2026

### Stable Release
- Raspberry MCP Gateway erreicht den Stable-Status für den dokumentierten Funktionsumfang.
- Sicherheits- und Betriebsdokumentation aktualisiert; vorhandene Testnachweise konsolidiert.
- AppArmor-Policy, Gateway-Code, Abhängigkeiten und sichere Standardeinstellungen bleiben unverändert.

### Qualität und Sicherheit
- AppArmor-Schutz im laufenden Gateway bestätigt; historischer Kernel-Negativtest bestanden.
- Isolierte Recovery-Tests auf dem Raspberry erfolgreich (17/17).

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
- Bekannte High-CVEs und verbleibende Nachweise sind in der Sicherheitsdokumentation beschrieben.
