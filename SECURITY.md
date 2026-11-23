# Sicherheit und verantwortlicher Betrieb

> **Dokumentationsentwurf.** Der aktuelle PUB-07/PUB-08-Kandidat ist noch nicht für die öffentliche Veröffentlichung oder produktive Installation freigegeben.

## Grundprinzipien

- Das Gateway ergänzt einen einzelnen Tunnel; es soll keine weitere parallel erreichbare Tunnelinstanz entstehen.
- **Least Privilege:** einen eigens vorgesehenen HA-Zugang verwenden; Berechtigungen und die Home-Assistant-MCP-Haupt-URL auf benötigte Lesezugriffe beschränken. Lokales `MCP_WRITE_ENABLED=false` verhindert nicht automatisch weitergehende Rechte des vorgelagerten HA-Tokens.
- Zugangsdaten (`CONTROL_PLANE_API_KEY`, `HA_ACCESS_TOKEN`, Tunnel-ID sofern sensibel) ausschließlich in den vom Supervisor verwalteten App-Einstellungen hinterlegen. Nicht im Quellcode, in Screenshots, Ausgaben oder Fehlerberichten veröffentlichen.
- Automatische App-Starts sind in den aktuellen Metadaten deaktiviert (`boot: manual`). Schreibzugriffe sind mit `MCP_WRITE_ENABLED=false` deaktiviert; `APPROVED_ACTION` ist leer und `BACKUP_RETENTION_MODE=off`.
- Vor Änderungen Backup und vollständige Diff-/SHA256-Vorschau prüfen. Die Freigabe für jede produktive Änderung ist separat einzuholen und darf nicht auf weitere Dateien oder Hashes übertragen werden. AppArmor und Dateisystembeschränkungen sind zusätzlich zu den Freigabemechanismen nötig.

## Grenzen des Systems

Die Home-Assistant-Konfiguration wird als Mount unter `/homeassistant_config` bereitgestellt und ist technisch **nicht** als read-only gemountet. Wirksame Schranken gegen unerlaubte Schreibzugriffe hängen vom korrekt geladenen `openai_mcp_tunnel`-AppArmor-Profil, den Anwendungsgates sowie den Host- und Supervisor-Einstellungen ab. Alle Verbotsfälle müssen auf dem tatsächlichen Zielsystem nachgewiesen werden; ein Quellcode-Review allein genügt nicht.

Der HA-MCP-Proxy erlaubt im gegenwärtigen Quellstand nur die drei Upstream-Werkzeuge `llm__GetDateTime`, `config__search_integrations` und `homeassistant__search_actions`. Die lokalen Gateway-Werkzeuge bleiben unabhängig davon vorhanden; sie müssen mit eigenen Berechtigungen und Einmalfreigaben geschützt werden.

## Offene Sicherheitsthemen vor Release

1. Im zuletzt geprüften nativen ARM64-Build meldete Grype **14 High-Matches zu neun CVE-IDs** und keine Critical. Die Befunde für SQLite und OpenSSL sind weder als behoben noch als akzeptiert markiert. Die bestehende Freigabeprüfung bleibt bis zu technisch belegten Entscheidungen bzw. einer ausdrücklichen Restrisikogenehmigung gesperrt. Pauschales Unterdrücken oder ungeprüfte Edge-Upgrades sind keine Lösung.


**Bekannte offene IDs des zuletzt geprüften Builds (SQLite/OpenSSL):** `CVE-2026-119586`, `CVE-2026-119379`, `CVE-2026-119374`, `CVE-2026-119373`, `CVE-2026-124709`, `CVE-2026-107494`, `CVE-2026-121482`, `CVE-2026-84786` und `CVE-2026-107493`. Diese Liste ist auf den früher geprüften Containerpaketstand bezogen und **keine** Zusage über die aktuelle Sicherheitslage späterer Selbstbauten. Die Source-only-Veröffentlichung beseitigt keine in den gepinnten Abhängigkeiten verbliebene Schwachstelle. Alle neun Entscheidungen sind intern noch `pending`; weder pauschal als nicht anwendbar noch als akzeptiert markiert. Für Installation auf produktivem HAOS sind eine aktuelle Paket-/CVE-Bewertung und eigene geprüfte Betriebsfreigabe erforderlich.

2. **OCI-Herkunft nachgewiesen:** Die offizielle SLSA-v1-Attestierung wurde für den exakten gepinnten OCI-Index-Digest mit GitHub CLI verifiziert, einschließlich OpenAI-Releaseworkflow, Tag und Quellcommit. Der abweichende Hash eines separat verteilten Release-ZIP-Binarys ist kein Gegenbeweis für das attestierte OCI-Image; dessen Byteidentität wird nicht behauptet. Dies ist kein Ersatz für die übrigen Sicherheitsprüfungen.
3. Die integrierte Laborabnahme auf isoliertem ARM64-HAOS/Supervisor ist weiterhin **NOT_RUN**: AppArmor-Allow-/Deny-Nachweise, Tunnel, MCP/Netzwerk, Neustart, Backup und Recovery. Dieser Nachweis ist für eine **als geprüft beworbene Installation oder ein produktives Update** erforderlich, nicht für den eng begrenzten Source-only-Snapshot mit ausdrücklicher Kennzeichnung seines Teststands. Ältere, privat getestete Versionen gelten nicht als Abnahme des geänderten GitHub-Kandidaten.
4. Die finale Quellbaumprüfung muss private Daten, Fremdcode, erforderliche Lizenz-/Copyright-Hinweise, Dokumentation und ein sauberes neues Git-History-Root umfassen.

## Vor Änderungen und bei Störungen

Erst Zustände und bereinigte Protokolle prüfen, dann gezielt ändern. Änderungen an produktivem Home Assistant nur nach ausdrücklicher Einzelfreigabe. Bei unerwarteten Schreibrechten oder einem fehlenden AppArmor-Enforce-Profil den Gateway-Betrieb stoppen, statt die Sicherheitsschranken zu lockern.

Vor einem Upgrade ist eine überprüfte Sicherung des funktionierenden Stands erforderlich. Ein Rollback muss anhand eines **tatsächlich geprüften** früheren App-/Quellstands und dessen Abhängigkeiten möglich sein; ein Git-Checkout allein stellt keine HA-Konfiguration oder vorhandene Daten wieder her.

## Meldung von Sicherheitsproblemen

Keine Zugangsdaten, internen Adressen, Konfigurationsdateien oder personenbezogenen Daten in öffentliche Issues einstellen. Vor einer Veröffentlichung **GitHub Private Vulnerability Reporting** im neuen öffentlichen Repository aktivieren und das dortige private Meldeformular in dieser Datei verlinken. Bis zur tatsächlichen Aktivierung ist **kein privater Meldeweg als verfügbar zu behaupten**; öffentliche Issues dürfen keine sensiblen Meldungen enthalten.
