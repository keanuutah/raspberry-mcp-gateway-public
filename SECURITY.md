# Sicherheit und verantwortlicher Betrieb

> **Öffentliche Quellfassung v1.1.0 (experimental).** Als Quellcode veröffentlicht; noch keine HAOS-Produktions- oder Installationsfreigabe. Es wird kein vorgebautes Container-Image angeboten.

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

1. Im zuletzt geprüften nativen ARM64-Build meldete Grype **14 High-Matches zu neun CVE-IDs** und keine Critical. Die neun bekannten High-CVEs wurden für die geprüften betroffenen Paketversionen einzeln als Restrisiken bewertet und dokumentiert; unterstützte Stable-Fixversionen waren beim letzten Abgleich nicht verfügbar. Das geänderte Gate hat Regressionstests bestanden. Ein offizieller erfolgreicher Sicherheits-Gate-Lauf für den aktuellen Quellstand ist damit noch nicht belegt. Pauschales Unterdrücken oder ungeprüfte Edge-Upgrades sind keine Lösung.


**Bekannte offene IDs des zuletzt geprüften Builds (SQLite/OpenSSL):** `CVE-2026-119586`, `CVE-2026-119379`, `CVE-2026-119374`, `CVE-2026-119373`, `CVE-2026-124709`, `CVE-2026-107494`, `CVE-2026-121482`, `CVE-2026-84786` und `CVE-2026-107493`. Diese Liste ist auf den früher geprüften Containerpaketstand bezogen und **keine** Zusage über die aktuelle Sicherheitslage späterer Selbstbauten. Die Source-only-Veröffentlichung beseitigt keine in den gepinnten Abhängigkeiten verbliebene Schwachstelle. Alle neun High-Risiken sind für den geprüften Paketstand einzeln dokumentiert und unter fortgeltenden technischen Bedingungen akzeptiert. Diese Bewertungen sind keine Behauptung, dass Schwachstellen behoben oder ausgeschlossen sind. Für die produktive HAOS-Installation bleibt eine separate Freigabe erforderlich.

2. **OCI-Herkunft nachgewiesen:** Die offizielle SLSA-v1-Attestierung wurde für den exakten gepinnten OCI-Index-Digest mit GitHub CLI verifiziert, einschließlich OpenAI-Releaseworkflow, Tag und Quellcommit. Der abweichende Hash eines separat verteilten Release-ZIP-Binarys ist kein Gegenbeweis für das attestierte OCI-Image; dessen Byteidentität wird nicht behauptet. Dies ist kein Ersatz für die übrigen Sicherheitsprüfungen.
3. Die integrierte Laborabnahme auf isoliertem ARM64-HAOS/Supervisor ist weiterhin **NOT_RUN**: AppArmor-Allow-/Deny-Nachweise, Tunnel, MCP/Netzwerk, Neustart, Backup und Recovery. Dieser Nachweis ist für eine **als geprüft beworbene Installation oder ein produktives Update** erforderlich, nicht für den eng begrenzten Source-only-Snapshot mit ausdrücklicher Kennzeichnung seines Teststands. Ältere, privat getestete Versionen gelten nicht als Abnahme des geänderten GitHub-Kandidaten.
4. Der öffentliche Quellbaum wurde als minimierter Snapshot mit eigener Git-Historie veröffentlicht. Rechte-/Lizenzhinweise und neue Versionsänderungen sind weiterhin vor jeder Veröffentlichung zu prüfen.

## Vor Änderungen und bei Störungen

Erst Zustände und bereinigte Protokolle prüfen, dann gezielt ändern. Änderungen an produktivem Home Assistant nur nach ausdrücklicher Einzelfreigabe. Bei unerwarteten Schreibrechten oder einem fehlenden AppArmor-Enforce-Profil den Gateway-Betrieb stoppen, statt die Sicherheitsschranken zu lockern.

Vor einem Upgrade ist eine überprüfte Sicherung des funktionierenden Stands erforderlich. Ein Rollback muss anhand eines **tatsächlich geprüften** früheren App-/Quellstands und dessen Abhängigkeiten möglich sein; ein Git-Checkout allein stellt keine HA-Konfiguration oder vorhandene Daten wieder her.

## Meldung von Sicherheitsproblemen

Keine Zugangsdaten, internen Adressen, Konfigurationsdateien oder personenbezogenen Daten in öffentliche Issues einstellen. Für vertrauliche Sicherheitsmeldungen das GitHub-Verfahren zur privaten Schwachstellenmeldung des Repositories nutzen, sofern es im Repository aktiviert und sichtbar ist. Keine sensiblen Informationen in öffentliche Issues schreiben.
