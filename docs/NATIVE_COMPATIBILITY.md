# Native Softwarekompatibilität unter macOS Tahoe

Quellenprüfung: 10. Oktober 2026. Ziel ist ein nativer Intel-Boot auf dem Samsung
Galaxy Book5 Pro 16, Core Ultra 5 226V, Arc 130V. Der Rechner läuft bislang unter
Windows. Es liegt keine macOS-Anwendungsinventur und keine native Geräteprobe
vor. Windows-Programmnamen sagen nicht aus, welche macOS-Ausgabe installiert
werden soll; der Prüfer untersucht deshalb ausschließlich ausdrückliche
`--app`-Auswahlen.

## Bereits belegte Grenzen

| Abhängigkeit | Bedeutung für dieses Intel-Ziel | Nachweis und offene Prüfung |
| --- | --- | --- |
| ARM-only-Anwendung | Ein reines `arm64`-/`arm64e`-Executable enthält keinen nativen Intel-Code. Rosetta bietet dafür keinen umgekehrten Übersetzungspfad. | Apple beschreibt Rosetta als Intel-zu-Apple-Silicon-Übersetzung. Der Prüfer liest die Architektur der ausgewählten Hauptdatei. |
| Universal- oder Intel-Anwendung | Eine passende `x86_64`-Datei ist eine notwendige Voraussetzung. Plug-ins, Bibliotheken, CPU-Merkmale und Laufzeitverhalten bleiben eigene Voraussetzungen. | Mach-O- und Info.plist-Metadaten; kein Startversuch. Ein alleiniger `x86_64h`-Slice bleibt wegen zusätzlicher CPU-Anforderungen unbestätigt. |
| 32-Bit-Anwendung | Tahoe unterstützt den früheren 32-Bit-App-Pfad nicht. | Apple: Unterstützung endete mit macOS Catalina. |
| Metal 4 | Apples unterstützte Mac-Hardware für Metal 4 verwendet Apple Silicon. Unsere Xe2-Hardware allein schafft keinen von Apple angebotenen Intel-Metal-4-Pfad. | Apple-Metal-Unterstützungstabelle und WWDC25; ein eigener zukünftiger Treiber wäre separat zu implementieren und zu testen. |
| Metal/CoreImage/WindowServer | Vorhandene Frameworks oder ein laufender WindowServer beweisen keinen qualifizierten Arc-Accelerator. | `MTLCopyAllDevices` zählt API-Geräte; Shaderausführung und Desktop-Compositing bleiben ungetestet. |
| Hardware-Videodecode | Linux-/Windows-Codec-Fähigkeiten ersetzen keine funktionierende macOS-VideoToolbox-Anbindung. | `VTIsHardwareDecodeSupported` meldet H.264-, HEVC- und AV1-Unterstützung; echte Decode-/Encode-Ausführung fehlt. |
| Alte AGL-Nutzung | Tahoe entfernt AGL aus dem SDK; AGL-Symbole haben unter 64-Bit keinen Effekt. Apple erklärt ausdrücklich, dass OpenGL im SDK verbleibt. | Eine gelinkte AGL-Abhängigkeit löst einen Hinweis aus. Das beweist weder konkrete AGL-Aufrufe noch ein generelles OpenGL-Verbot. |
| Nächste macOS-Hauptversion | Apple kündigte Tahoe als letzte Version für Intel-Macs an. | WWDC25 Platforms State of the Union. Das Modul qualifiziert kein späteres Apple-Silicon-Betriebssystem für diesen Intel-Rechner. |
| Kernel-Ladepolicy | Ein fertiges oder signiertes Kext ist nicht automatisch geladen. SIP-/Gatekeeper-Zustände sind keine einzelne Treiberabnahme. | Apple dokumentiert Kext-Freigabe und Signaturprüfung; das Modul liest nur Zustände und ändert keine Policy. |
| Firmware Secure Boot | Samsung-UEFI-Secure-Boot muss im fertigen Aufbau separat unterstützt und geprüft werden. OpenCore `SecureBootModel`, SIP und Gatekeeper bestätigen ihn nicht. | Der Bericht enthält `required_enabled=true` und weiterhin `state=unverified`; es erfolgt keine Firmware- oder Schlüsseländerung. |

Die Arc-Grafikentwicklung, I2C-/GPIO-/HID-, Audio-, Funk- und HDR-Implementierung
bleiben eigene Module. Dieser Bericht repariert keine fehlende Geräteanbindung.
Ein Apple-Silicon-Feature lässt sich nicht allein durch Umbenennen einer
Geräte-ID oder einen Universal-App-Download auf Intel herstellen.

OpenCore beschreibt eine vollständige sichere Bootkette mit mehreren Schritten:
Apple Secure Boot, passende Konfiguration, Signierung der EFI-Komponenten,
Vault und im Firmware-Trust-Store hinterlegte Zertifikate. Sein separater
Apple-Secure-Boot-Abschnitt nennt Einschränkungen für unsignierte Kexts.
Ein bisher unsignierter Diagnose-Build erfüllt deshalb noch nicht die
Gesamtabnahme. Daraus folgt kein generelles Verbot unsignierter Kexts allein
durch Samsung-UEFI-Secure-Boot; Bootloader-Verifikation und macOS-Ladepolicy
müssen zusammen geprüft werden. Das Modul ändert keine dieser Einstellungen.
[OpenCore-Konfiguration, SecureBootModel und UEFI Secure Boot](https://github.com/acidanthera/OpenCorePkg/blob/master/Docs/Configuration.tex)

## Welche Daten der Prüfer tatsächlich erfasst

Auf Darwin liest er `sw_vers -productVersion`, die Prozessarchitektur, die
Existenz ausgewählter System-Framework-Verzeichnisse sowie rein lesende
`csrutil status`, `spctl --status` und `pgrep -x WindowServer`-Ergebnisse.
Ausgaben werden nur als feste Zustände oder validierte Versionszahlen
übernommen. Prozess-IDs, stderr, vollständige Ausgaben und unbekannte
Metadaten erscheinen nicht im Bericht.

Metal wird über öffentliche Geräteenumeration in einer eigenen
Autorelease-Pool-Lebensdauer abgefragt. Die gehaltene NSArray wird freigegeben.
Der Prüfer erzeugt keine CommandQueue und reicht keine GPU-Befehle ein.
Die VideoToolbox-Abfrage prüft nur die gemeldete Decode-Unterstützung.
Sie registriert keine zusätzlichen Codecs und startet keine Session.

Pro ausgewählter App liest er ausschließlich `Contents/Info.plist` und den
dort angegebenen Haupt-Executable-Header. Einzelne explizite Mach-O-Dateien
sind ebenfalls möglich. Thin-/Fat-32-/Fat-64-Header, Byteordnung, Grenzen,
überlappende Slices, CPU-Metadaten und Load-Command-Längen werden geprüft.
Aus Bibliotheksnamen bleiben nur feste System-Framework-Bezeichnungen erhalten.
Das ist keine vollständige Signatur- oder dyld-Validierung: Segment-Mappings,
sämtliche transitive Abhängigkeiten, Plug-ins und Anwendungsressourcen werden
nicht geprüft. Es gibt keinen allgemeinen App-, Benutzer- oder Plattenscan.

Vor dem Öffnen müssen sowohl die Hauptdatei als auch die App-Metadaten reguläre
Dateien sein. Das Öffnen verwendet `O_NONBLOCK` und `O_NOFOLLOW`, soweit das
Betriebssystem diese Flags anbietet. Ein erneutes `fstat` prüft Dateityp und
Identität vor dem ersten Lesen. Eine FIFO oder ein nach der Vorprüfung
ausgetauschter Dateiinhaltsträger wird somit nicht als lesbare App-Datei
angenommen. Diese Prüfung ist kein allgemeiner Schutz gegen sämtliche Änderungen
an App-Inhalten während ihrer Prüfung.

JSON-Berichte werden über eine private temporäre Datei im gleichen Zielordner
geschrieben, geflusht und vollständig ersetzt. Ein Fehler vor dem Ersetzen
erhält den alten Bericht. Die CLI gibt für Schreibfehler nur festen Text und
Exitcode 3 aus. Temporäre Dateien werden bei Fehlern entfernt, soweit die
Dateisystemrechte dies erlauben. Lokale JSON-Berichte, Python-Caches und auch
verschachtelte Arbeitslisten bleiben durch `.gitignore` privat.

## Berichtszustände richtig lesen

`blocked` bei einer App bedeutet eine konkret erfasste fehlende Intel- oder
macOS-Versionsvoraussetzung. `unverified` bezeichnet fehlende, ungültige oder
noch nicht belegte Voraussetzungen. `metadata_prerequisites_satisfied` bestätigt
nur die hier geprüften Metadaten; `launch_tested=false` bleibt bestehen.

`no_device_reported` ist ein erfolgreich abgefragtes Metal-Ergebnis ohne Gerät.
`query_unavailable` bezeichnet eine nicht ausführbare Abfrage und ist kein
Nachweis fehlender Hardwareunterstützung. `api_reported` bestätigt lediglich
die Antwort der jeweiligen API. Ein Bericht mit `macos-runtime-observed`
beweist weder einen physischen Samsung-Boot noch das Arc-130V-Gerätematching.
CI- oder Fremd-Mac-Berichte dürfen nicht als Samsung-Geräteabnahme gelten.

Die 30 Windows-Tests verwenden synthetische Mach-O-Dateien und simulierte
macOS-Antworten. Sie prüfen die Entscheidungs- und Fehlergrenzen sowie
Datensparsamkeit, Spezialdateiablehnung, Dateitausch und erhaltene Berichte bei
Speicherfehlern. Auf POSIX läuft im gleichen Test zusätzlich eine echte FIFO-
Vorprüfung. Die Tests qualifizieren keine Apple-Framework-Binärschnittstelle
am Zielgerät. Dort folgen die tatsächliche Tool-Ausführung, gezielte
Anwendungsstarts und getrennte Grafik-/Video-/Boot-Abnahmen.

Der separate CI-Workflow verwendet gepinnte Checkout-/Artifact-Aktionen und
nur lesende Repositoryrechte. Windows und `macos-26-intel` führen die Tests aus.
Der macOS-Job führt zusätzlich den Prüfer ohne App-Auswahl aus und kontrolliert
die Metal-/VideoToolbox-API-Abfragen sowie die weiterhin unbestätigten
Zielgeräte-, Ausführungs- und Secure-Boot-Felder. Hochgeladen werden nur
bereinigte Ergebnis-JSONs mit `evidence_context` für den CI-Host, keine
internen Pläne oder Arbeitslisten. Ein erfolgreicher CI-Host-Lauf würde diese
Host-API-Abfragen bestätigen; die Samsung-Geräteabnahme bliebe offen.

## Primärquellen

- [Apple: Metal-Unterstützung](https://support.apple.com/en-us/102894)
- [Apple: Intel-Apps und Rosetta](https://support.apple.com/en-us/102527)
- [Apple: 32-Bit-App-Unterstützung](https://support.apple.com/en-us/103076)
- [Apple: macOS Tahoe 26 Release Notes, AGL](https://developer.apple.com/documentation/macos-release-notes/macos-26-release-notes)
- [Apple: Platforms State of the Union, WWDC25](https://developer.apple.com/videos/play/wwdc2025/102/)
- [Apple: MTLCopyAllDevices](https://developer.apple.com/documentation/metal/mtlcopyalldevices())
- [Apple: VTIsHardwareDecodeSupported](https://developer.apple.com/documentation/videotoolbox/vtishardwaredecodesupported(_:))
- [Apple: LSMinimumSystemVersion](https://developer.apple.com/documentation/bundleresources/information-property-list/lsminimumsystemversion)
- [Apple Open Source: Mach-O-Header und Load Commands](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [Apple: Systemextensions und Kernel-Ladepolicy](https://support.apple.com/guide/deployment/system-extensions-in-macos-depa5fb8376f/web)
- [OpenCore: eigene Secure-Boot-Modelle und Konfiguration](https://github.com/acidanthera/OpenCorePkg/blob/master/Docs/Configuration.tex)
