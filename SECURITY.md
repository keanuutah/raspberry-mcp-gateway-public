# Security Policy & Architecture

> **Raspberry MCP Gateway v1.1.1 · Experimental · Stand 24.11.2026**  
> Öffentlicher Quellcode für eine Home-Assistant-OS-App (ARM64). Es wird **kein vorgebautes OCI-/GHCR-Image** bereitgestellt. Die App wurde auf einer privaten HAOS-Installation betrieben und in definiertem Umfang getestet; daraus folgt **keine allgemeine Produktionsfreigabe**.

## 1. Security Overview

Das Gateway verbindet einen MCP-Client über **einen Tunnel** mit Home Assistant. Das Sicherheitskonzept beruht auf *Least Privilege*, *Fail Closed* und überprüfbaren, einzeln freigegebenen Änderungen.

| Schutzebene | Umsetzung |
| --- | --- |
| **Zugriff auf Home Assistant** | HA-MCP-Proxy mit expliziter Upstream-Allowlist; lokale Gateway-Werkzeuge werden separat abgesichert. |
| **Sichere Standardeinstellungen** | `MCP_WRITE_ENABLED=false`, `APPROVED_ACTION=""`, `BACKUP_RETENTION_MODE=off`, `boot: manual`. |
| **Änderungskontrolle** | Vor geschützten Schreibvorgängen Vorschau und Diff; datei- und SHA256-gebundene Einzelfreigaben. |
| **Dateisystem** | AppArmor-Policy und Anwendungsgates begrenzen zulässige Schreibbereiche. |
| **Supply Chain** | Gepinnte Build-Abhängigkeiten, ARM64-Build-Nachweise, SPDX-SBOM und Grype-Auswertung. |
| **Release-Prozess** | Öffentliche GitHub-Actions-Prüfung für Version/Changelog sowie aktives Branch-Ruleset für `main`. |

**Betriebsprinzip:** Keine zweite gleichzeitig aktive Tunnelinstanz mit denselben Zugangsdaten.

## 2. Security Controls

### Berechtigungen und Geheimnisse

- Für die Home-Assistant-Verbindung einen **möglichst eingeschränkten Zugang** verwenden. `MCP_WRITE_ENABLED=false` begrenzt lokale Gateway-Schreibwerkzeuge, **nicht** automatisch die Rechte des HA-Tokens.
- `CONTROL_PLANE_API_KEY`, `HA_ACCESS_TOKEN` und gegebenenfalls sensible Tunnelkennungen ausschließlich über die lokalen, vom Supervisor verwalteten App-Einstellungen konfigurieren; niemals in Commits, Screenshots, Ausgaben oder öffentlichen Fehlerberichten veröffentlichen.
- Die HA-MCP-Upstream-Allowlist im geprüften Quellstand umfasst `llm__GetDateTime`, `config__search_integrations` und `homeassistant__search_actions`. Die weiteren lokalen Gateway-Funktionen unterliegen eigenen Berechtigungen und Freigabeprüfungen.

### AppArmor und YAML Guard

Der Home-Assistant-Konfigurations-Mount unter `/homeassistant_config` ist technisch **schreibbar eingebunden** (`read_only: false`). Das bedeutet **keine** pauschale Schreibfreigabe: Die mitgelieferte AppArmor-Policy erlaubt gezielte Schreibzugriffe insbesondere auf unmittelbare Dateien unter `/homeassistant_config/packages/` sowie bestimmte Backup- und Quarantänepfade. Anwendungsgates und Freigaben bilden weitere Schutzschichten.

- Geschützte YAML-Änderungen: zunächst Datei lesen, Änderungsplanung mit Diff und SHA256 prüfen, anschließend **separate einmalige Genehmigung** für genau diese Änderung; erst danach Commit und Backup-Verifikation.
- Fehlende oder unpassende Freigaben müssen scheitern; Freigaben nicht dateiübergreifend oder für andere Hashes wiederverwenden.
- AppArmor-Quelltext allein beweist **nicht**, welche Policy der Kernel tatsächlich geladen hat. Ein erfolgreicher Process-Enforce-Nachweis ist ebenfalls kein vollständiger Dateisystem-Negativtest.

## 3. Verification & CI

### Bestätigte Nachweise

| Bereich | Nachweis und Grenze |
| --- | --- |
| **HAOS-Betrieb v1.1.1** | Ein Tunnel sowie lesende MCP-, YAML- und Dashboard-Funktionen auf der installierten GitHub-App erfolgreich geprüft. |
| **AppArmor v1.1.1** | Laufender MCP-Prozess und Container-Init-Prozess melden passendes Profil im Modus `enforce`; Diagnose `overall=enforce_confirmed`. Die Kernel-Profilliste via `securityfs` war nicht verfügbar. |
| **Backup-Prüfung v1.1.1** | Vorhandenes Gateway-Backup lesend auf Existenz, Größe und erwarteten SHA256-Wert geprüft. |
| **Historische Security-/Recovery-Tests** | Am 18.11.2026 wurden unter damaligem Teststand ein verbotener Schreibzugriff (`errno=13`), isolierte YAML-Backup-Wiederherstellungen mit Byte-/Hash-Vergleich, Dashboard-Snapshot-Restore und Backup-Retention geprüft. Diese Nachweise gelten **nur für ihren damaligen Umfang und Stand**. |
| **Private CI / ARM64** | Offline-Regressionen sowie native ARM64-Build-, Lizenz-, SBOM- und CVE-Prüfungen im privaten Entwicklungsprozess dokumentiert; nicht gleichzusetzen mit einer vollständigen v1.1.1-HAOS-Abnahme. |
| **Public Release Gate** | GitHub Actions prüft App-Version gegen neuesten Changelog-Abschnitt und vorhandene Release-Notizen. Aktives Ruleset [Public Release Gate #27946217](https://github.com/keanuutah/raspberry-mcp-gateway-public/rules/27946217) verlangt einen Pull Request und den erfolgreichen Check `App version matches changelog` für `main`; keine Bypass-Ausnahmen. |

Die öffentliche CI ist eine **Release-Metadatenprüfung**; sie ersetzt keine vollständige Sicherheits-, Lizenz-, Build- oder Integrationsprüfung.

### Grenzen der Abnahme

Für v1.1.1 sind **nicht** als vollständiger integrierter Labornachweis bestätigt: neue gezielte Kernel-AppArmor-DENIED-Tests für sämtliche relevanten Pfade, kontrolliert abgebrochene Quarantäne mit Recovery sowie ein vollständiger Neustart-/Disaster-Recovery-Ablauf. Historische Testergebnisse werden nicht als neue versionsspezifische Tests ausgegeben.

## 4. Known Risks & Limitations

### Bekannte High-CVEs im zuletzt geprüften ARM64-Build

Der dokumentierte Grype-Scan meldete **14 High-Matches zu neun unterschiedlichen CVE-IDs**, **0 Critical**. Die betroffenen Paketversionen wurden einzeln bewertet; die neun High-Risiken wurden für den **konkret geprüften Paket-/Image-Stand** unter dokumentierten technischen Bedingungen als `accepted_risk` behandelt.

**SQLite/OpenSSL – bekannte CVE-IDs:**

- `CVE-2026-119586`, `CVE-2026-119379`, `CVE-2026-119374`, `CVE-2026-119373`
- `CVE-2026-124709`, `CVE-2026-107494`, `CVE-2026-121482`, `CVE-2026-84786`, `CVE-2026-107493`

Beim letzten dokumentierten Paketabgleich standen keine unterstützten Stable-Fixversionen für die betroffenen Stände bereit. **Risikoakzeptanz bedeutet keine Behebung.** Sie gilt nicht automatisch für neue Images, geänderte Pakete oder spätere Builds. Ein erneuter offizieller **PASS** des Container-CVE-Release-Gates nach den Entscheidungen ist für den aktuellen Stand **nicht nachgewiesen**. Neue Fixversionen erfordern erneute Prüfung; Schwachstellen werden nicht pauschal unterdrückt.

### OCI-Herkunft und Lizenzierung

Für den genau gepinnten OpenAI-Tunnel-OCI-Index-Digest wurde eine offizielle **SLSA-v1-Attestierung** einschließlich Build-Workflow, Tag und Quellcommit verifiziert. Das belegt die Herkunft **dieses OCI-Artefakts**, nicht die Byteidentität eines separat angebotenen ZIP-Binarys oder die Sicherheit des gesamten Gateway-Images.

Der öffentliche Quellbaum enthält nur einen bereinigten Snapshot mit eigener Historie. Rechte, Fremdkomponenten-Lizenzen und neue Abhängigkeiten sind bei jeder relevanten Änderung zu prüfen. Details zu bekannten Risiken und Nutzungshinweisen stehen zusätzlich im Repository.

## 5. Vulnerability Reporting & Responsible Operation

**Vertrauliche Sicherheitsmeldung:** Auf der [Security-Seite des Repositories](https://github.com/keanuutah/raspberry-mcp-gateway-public/security) nach **„Report a vulnerability“** suchen, **sofern** GitHub Private Vulnerability Reporting dort angeboten wird. Die Aktivierung dieser Funktion wird hier nicht ungeprüft zugesichert. Keine Exploitdetails, Zugangsdaten, internen Adressen, Home-Assistant-Konfigurationen oder personenbezogenen Daten in öffentlichen Issues veröffentlichen.

**Betrieb und Änderungen:** Erst Zustände und bereinigte Logs prüfen, dann gezielt korrigieren. Vor jedem produktiven Eingriff ein verifiziertes Backup und einen realistischen Rückfallweg bereithalten; für Änderungen an produktivem Home Assistant eine eigene ausdrückliche Freigabe einholen. Bei fehlender AppArmor-Enforce-Bestätigung oder unerwarteten Schreibrechten Betrieb und Ursache prüfen, **nicht** Sicherheitsschranken lockern.

Ein Git-Checkout allein stellt weder Home-Assistant-Daten noch Supervisor-App-Zustand wieder her.

---

*Diese Security Policy dokumentiert den öffentlich nachvollziehbaren Sicherheitsansatz und den ausdrücklich begrenzten Teststand von v1.1.1; sie stellt keine Zertifizierung oder Garantie für fremde Installationen dar.*
