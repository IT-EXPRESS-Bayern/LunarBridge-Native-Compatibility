# LunarBridge Native Compatibility

Eigenständiger, lesender Software-Prüfer für das geplante native macOS Tahoe
auf einem Samsung Galaxy Book5 Pro 16 mit Intel Core Ultra 5 226V und Arc 130V.
Das Modul benötigt weder LunarBridge-Grafikcode noch andere Treiberpakete.

Der Prüfer dokumentiert Architektur- und Betriebssystemanforderungen ausdrücklich
ausgewählter macOS-Anwendungen sowie gemeldete Grafik-, Medien- und Policyzustände.
Er startet keine Anwendung und übermittelt keine Daten. Er installiert keine
Treiber und ändert keine Sicherheits-, EFI- oder Firmwareeinstellungen.

## Ausführung

Python 3.10 oder neuer auf dem später gebooteten macOS:

```sh
python3 tools/native_compatibility.py --out reports/native-compatibility.json
python3 tools/native_compatibility.py --out reports/native-compatibility.json --app "/Applications/Beispiel.app"
```

Bis zu 16 `--app`-Argumente sind möglich. Die Auswahl wird im Bericht nur durch
`selection_index` in Eingabereihenfolge identifiziert. Appnamen, Benutzerpfade,
Bundle-IDs und private Bibliothekspfade werden nicht ausgegeben. Die
JSON-Zieldatei muss außerhalb von Apps, EFI und geschützten Systemverzeichnissen
liegen. Berichte werden vollständig in einer privaten temporären Datei im
Zielordner geschrieben und erst danach atomar ersetzt. Fehler vor dem Ersetzen
erhalten einen schon vorhandenen Bericht. Das Schreiben dieser ausdrücklich
ausgewählten Berichtsdatei und ihrer temporären Datei ist die einzige
beabsichtigte Dateiveränderung.

Unter Windows erstellt `native_compatibility.py` einen Bericht mit `unsupported-platform`; der Prozess
endet mit Code 2 und führt keine macOS- oder App-Prüfung aus. Code 0 auf macOS
bedeutet, dass der Bericht erstellt wurde. Er bestätigt keine vollständige
Kompatibilität. Ungültige CLI-Eingaben enden ebenfalls mit Code 2. Fehler beim
Speichern enden mit Code 3 und einem festen Fehlertext ohne Benutzerpfade.

## Aussagegrenzen und Prüfnachweis

Metal-Geräte oder VideoToolbox-Unterstützung werden als API-Meldungen erfasst.
Der Prüfer führt keinen Shader, Video-Decode oder GPU-Submit aus. WindowServer
kann auch ohne qualifizierte Grafikbeschleunigung vorhanden sein.
`native_target_boot_verified`, `gpu_execution_verified` und der Firmware-
Secure-Boot-Nachweis bleiben daher ausdrücklich unbestätigt.

30 Softwaretests prüfen Windows-Plattformschutz, synthetische Mach-O-Dateien,
Architektur-/Versionsgrenzen, Spezialdateien, Datensparsamkeit und Fehler beim
atomaren Schreiben:

```sh
python3 tests/test_native_compatibility.py
python3 tests/test_graphics_interfaces.py
```

Diese Tests sind keine Geräteprobe. Auf dem Samsung-Rechner läuft derzeit noch
kein macOS; die Framework- und Objective-C-Abfragen wurden noch nicht auf ihm
ausgeführt. Die CI führt die Tests unter Windows und `macos-26-intel` aus.
Auf dem macOS-CI-Host erfolgt zusätzlich eine lesende Framework-/API-Abfrage;
deren Bericht kennzeichnet ausdrücklich, dass dieser Rechner nicht das Samsung-
Zielgerät ist. Die CI-Workflow-Datei allein bestätigt noch keinen erfolgreichen
CI-Lauf. Umfang und Primärquellen stehen in
[NATIVE_COMPATIBILITY.md](docs/NATIVE_COMPATIBILITY.md).

GPL-3.0-only; kommerzielle Nutzung unter den Bedingungen von [LICENSE](LICENSE).

Ein zusätzlicher rein lesender Symbolprüfer untersucht ausdrücklich ausgewählte
Mach-O-Verbraucher und Provider sowie ausgewählte XNU-Exportlisten. Er läuft
auch unter Windows und unterscheidet Binärexporte, veröffentlichte Quellverträge
und weiterhin unbestätigte Kext-Ladbarkeit. 24 zusätzliche Tests prüfen diesen
Anschluss, malformed Symbol-/Exportdaten, Dateigrenzen und Datensparsamkeit.

```sh
python3 tools/graphics_interfaces.py --consumer "/Selected/Consumer" --provider "/Selected/ExtractedProvider" --out reports/interfaces.json
python3 tools/graphics_interfaces.py --consumer "/Selected/Consumer" --export-list "/Selected/IOKit.exports" --out reports/interfaces.json
```

Die konkrete Intel-Tahoe-Portierungsgrundlage, freie Schnittstellen, noch
fehlende private Grafik-ABI und lokale Belege echter vorhandener Binärdateien
stehen in [GRAPHICS_INTERFACE.md](docs/GRAPHICS_INTERFACE.md). Diese Erweiterung
registriert keinen Metal-Treiber und führt ausgewählte Programme nicht aus.
Die neue Mac-CI prüft dafür zusätzlich einen selbst kompilierten öffentlichen
Importfall. Das frühere CI-Ergebnis unten gilt weiterhin nur für dessen
angegebenen Quellstand.

Der erfolgreiche Online-Prüflauf und sein exakter Quellstand sind in [docs/CI_VALIDATION.json](docs/CI_VALIDATION.json) festgehalten. Spätere Dokumentations-Commits sind davon getrennt; dieser CI-Lauf ist kein Gerätefunktionstest auf dem Samsung.
