# Intel-Tahoe: Anschluss eines neuen Xe2-Grafiktreibers

Quellen- und lokale Dateiprüfung: 11. Oktober 2026. Ziel bleibt ein nativer
Intel-Boot auf dem Galaxy Book5 Pro 16 mit Arc 130V `8086:64A0`, Samsung
Subsystem `144D:C1DD`. macOS läuft bislang nicht auf dem Zielgerät.

Öffentliche IOKit-Schnittstellen erlauben einen eigenständigen PCI-Dienst,
einen eigenen UserClient, Speicherverwaltung und einen IOFramebuffer-Treiber.
Sie enthalten in den untersuchten Quellen keinen vollständigen Vertrag für
einen neuen, vom Tahoe-Metal-Laufzeitsystem ausgewählten Xe2-Treiber. Dafür
fehlen noch der moderne IOAccel-Anschluss, der Benutzermodus-Treibervertrag,
Shaderübersetzung und die reale Hardwareausführung. Weniger Recheneinheiten
oder langsamere Ausführung lösen diese Anschlussprobleme nicht.

## Konkret vorhandene öffentliche Verträge

| Schicht | Öffentlicher Ansatz | Was noch real nachgewiesen werden muss |
| --- | --- | --- |
| IOKit-Dienst und eigener UserClient | IOService/IOUserClient und IOServiceOpen/IOConnectCallMethod. Diese Schnittstellen gehören zu XNU bzw. IOKitUser. | Kextannahme, PCI-Matching, kontrollierte Methoden und Rückbau auf dem Ziel. Eigene Selektoren werden dadurch nicht zu Metal-Selektoren. |
| Gerätemapper und DMA | IOMapper::copyMapperForDevice; IODMACommand mit explizitem Mapper, vorbereiteten Deskriptoren und gemappten Segmenten. | Exportauflösung und echter Gerätemapper; DMA-Lebensdauer, IOMMU- und Xe2-Seitentabellen bleiben eigene Prüfungen. Ein zurückgegebenes Segment ist kein ausgeführter GPU-Befehl. |
| Bildausgabe | IOFramebuffer deklariert Apertur, Displaymodi, Pixelformate und Umschaltung. | Xe2-Displayhardware, interner eDP-Pfad, USB-C-Routing und Schlaf-/Aufwachabläufe. Ein einfacher Framebuffer belegt keine Metal-Beschleunigung. |
| Alte Accelerator-/Surface-Schnittstellen | IOAccelerator.h, IOAccelSurfaceConnect.h und IOAccelSurfaceControl.c sind öffentlich. | Ihre alten ID-, Lock-, Shape- und Flush-Verträge reichen nicht als Beschreibung des modernen IOAcceleratorFamily2-/Metal-Vertrags. |
| IOSurface für Anwendungen | IOSurfaceCreate und die dokumentierten Lookup-/Mach-Port-Funktionen beschreiben gemeinsame Bildspeicherobjekte. | Korrektes GPU-Mapping, Formate/Planes, Tiling und Synchronisation. IOSurfaceCreate stellt allein keinen Xe2-Accelerator bereit. |
| Metal für Anwendungen | MTLCopyAllDevices, MTLDevice.registryID und die Erzeugung einer Textur auf einem IOSurface sind dokumentiert. | Vom Metal-Laufzeitsystem ausgewählte Geräteimplementierung, passende Registry-Zuordnung, Shaderausführung und Completion/Fences. |

Apple beschreibt IOFramebuffer ausdrücklich als einfache Bildausgabe mit
separater Beschleunigung. Der aktuelle öffentliche IOAccelerator-Header
deklariert nur die Verwaltung von Accelerator-IDs. IOKitUsers alter Surface-
Code findet den Accelerator über Framebuffer-Registry-Eigenschaften und
öffnet einen Surface-UserClient. Das ist ein konkreter historischer Anschluss,
aber kein vollständiges modernes Metal-Treiber-ABI.
[Apple IOGraphics: IOFramebuffer](https://github.com/apple-oss-distributions/IOGraphics/blob/76285384ff0ce63965a21b8023bf6d7e447fcc19/IOGraphicsFamily/IOKit/graphics/IOFramebuffer.h),
[IOAccelerator](https://github.com/apple-oss-distributions/IOGraphics/blob/76285384ff0ce63965a21b8023bf6d7e447fcc19/IOGraphicsFamily/IOKit/graphics/IOAccelerator.h),
[IOKitUser: Surface-Anschluss](https://github.com/apple-oss-distributions/IOKitUser/blob/323ead896d04424f87184d8f6ff0cce811aab106/graphics.subproj/IOAccelSurfaceControl.c).

## Der nächste implementierbare Kernel-Anschluss: Mapper und DMA

Apples macOS-26.0-Quellliste nennt `xnu-12377.1.9`, `IOGraphics-599` und
`IOKitUser-100222.0.4`. Das XNU-Tag enthält folgende Exportverträge:

| Funktion/Symbol | Öffentliche Exportliste | Einordnung |
| --- | --- | --- |
| `__ZN8IOMapper19copyMapperForDeviceEP9IOService` | config/IOKit.exports | Der Gerätemapper-Anschluss ist als Exportvertrag vorhanden. |
| IODMACommand::withSpecification und OutputHost64 | config/IOKit.x86_64.exports | Die genaue Overload-Signatur muss mit den tatsächlichen Kext-Imports übereinstimmen. |
| IODMACommand::setMemoryDescriptor, clearMemoryDescriptor, prepare/complete | config/IOKit.exports | Die Ressourcenzustände müssen paarweise und auch bei Fehlern korrekt zurückgebaut werden. |
| IODMACommand::genIOVMSegments | config/IOKit.x86_64.exports | gen64IOVMSegments ist ein Header-Wrapper. Entscheidend ist der dadurch tatsächlich importierte Name. |

SHA256 der unveränderten Quelllisten:
`5435d901591777679419018e8051d33d614636f078e43aa08ef51bf9e088081d`
für IOKit.exports und
`c33616433824a14ded767ff24eb911b3d6499b9a859204f82cbd12c27fa51450`
für IOKit.x86_64.exports. Diese Dateien dokumentieren den veröffentlichten
Quellvertrag; sie sind keine aus einem gestarteten Tahoe-Kernel extrahierten
Exporttabellen. Die ausgelieferte Zielversion und dessen Kextlinker müssen
weiterhin separat geprüft werden.
[Apple: macOS-26.0-Quellliste](https://github.com/apple-oss-distributions/distribution-macOS/blob/main/release.json),
[XNU IOKit.exports](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/config/IOKit.exports),
[XNU Intel-Exportliste](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/config/IOKit.x86_64.exports).

Im neueren Header gibt copyMapperForDevice `OSPtr<IOMapper>` zurück. OSPtr.h
definiert OSPtr ohne `IOKIT_ENABLE_SHARED_PTR` ausdrücklich als gewöhnlichen
Zeiger. Die Schreibweise allein belegt deshalb keinen Bruch mit dem alten
SDK-Zeigerinterface. Symbolnamen allein prüfen aber auch keine Rückgabetypen,
Aufrufkonventionen oder Vtables. Der Mapper sucht zunächst die Eigenschaft
`iommu-parent`; fehlt sie, kann er keinen Gerätemapper liefern. Das muss auf
dem späteren nativen Ziel beobachtet werden.
[IOMapper-Header](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/iokit/IOKit/IOMapper.h),
[OSPtr-Aliasregeln](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/libkern/libkern/c%2B%2B/OSPtr.h),
[Mapper-Implementierung](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/iokit/Kernel/IOMapper.cpp).

## Die noch offene moderne Grafik-ABI

Für einen eigenen nativen Xe2-Treiber müssen mindestens vier Verträge
zusammenpassen:

1. Kernel: Speicherobjekte, Task-Isolation, GPU-VA, IOSurface-Backing,
   Command-Queue/Context, Completion/Fences, Reset und sichere Fehlerbehandlung.
2. Benutzermodus: Metal-Geräteauswahl, Ressourcenobjekte und die genauen
   Kernel-UserClient-Selektoren samt Structgrößen und Shared-Memory-Protokollen.
3. Shaderpfad: Metal-Eingabe-/Bibliotheksformate und tatsächlich ausführbarer
   Xe2-Code mit den benötigten Ressourcen- und Dispatch-Metadaten.
4. Display/WindowServer: kompatible geteilte Surfaces, Bildübergabe und
   Synchronisation mit der tatsächlich angeschlossenen Displayhardware.

Die untersuchten öffentlichen Header liefern hierfür keinen vollständigen
aktuellen IOAccelDevice2-/IOAccelContext2-/IOAccelSharedUserClient2-Vertrag und
keinen dokumentierten externen Metal-Treiberregistrierungsweg. Apples
DriverKit-Dokumentation stellt unter anderem PCI-, USB-, HID-, Netzwerk- und
Audiotreiberfamilien bereit; sie dokumentiert damit keinen ersatzweisen
Metal-GPU-Vertrag. Das ist eine Grenze dieser Quellenprüfung, kein Beweis,
dass eine eigene Implementierung grundsätzlich unmöglich wäre.
[Apple DriverKit](https://developer.apple.com/documentation/driverkit),
[Apple PCIDriverKit](https://developer.apple.com/documentation/pcidriverkit).

Eine öffentliche Referenz für versionsspezifische private Anschlusspunkte ist
WhateverXe am untersuchten Quellstand
`61a449255d385aeb468f64e5d5042e126f387b90`: Dort werden unter anderem
IntelAccelerator, IGAccelCommandQueue, IOGraphicsAccelerator2 und
IntelMTLRenderFunctions über konkrete Symbol-/Offsetprüfungen angepasst.
Dessen README nennt Big Sur Build 20G1443 und ausgewählte Xe-LP-Geräte.
Lunar-Lake-Xe2 und Tahoe sind dadurch nicht qualifiziert. Der dort benötigte
geänderte Root-Grafikstack ist ebenfalls keine Abnahme unserer verlangten
sicheren Bootkette. Diese Referenz liefert Untersuchungspunkte, keine auf
Tahoe übertragbaren Vtable-Offsets oder eine fertige Arc-130V-Lösung.
[WhateverXe-Quellstand](https://github.com/b00t0x/WhateverXe/tree/61a449255d385aeb468f64e5d5042e126f387b90),
[versionsabhängige Anschlüsse](https://github.com/b00t0x/WhateverXe/blob/61a449255d385aeb468f64e5d5042e126f387b90/WhateverXe/kern_xe.cpp).

Aus einer passenden lokalen Intel-Tahoe-Installation sind daher zuerst
versionsgenaue Header-/Export- und UserClient-Nachweise erforderlich. Private
Objektlayouts, Selektoren, Plugin-Initialisierung und Befehls-/Surfaceformate
benötigen zusätzliche ABI-Untersuchung bzw. eine eigene kompatible
Implementierung. Proprietäre Treiber, Frameworks und Cache-Auszüge bleiben
lokal; dieses Repository verteilt keine solchen Dateien.

Ein späterer Gerätebindungsnachweis sollte `MTLDevice.registryID` intern mit
dem IOKit-Registry-Eintrag vergleichen und dessen PCI-Provider auf
`8086:64A0`/`144D:C1DD` prüfen. Eine passende Registry-ID bestätigt die
Zuordnung, noch keinen ausgeführten Shader. Eine auf diesem Gerät erstellte
IOSurface-Textur mit anschließendem verifiziertem Bild-/Compute-Ergebnis wäre
eine eigene nächste Ausführungsprobe.
[Apple: registryID](https://developer.apple.com/documentation/metal/mtldevice/registryid),
[IOSurface-Texturerzeugung](https://developer.apple.com/documentation/metal/mtldevice/maketexture(descriptor:iosurface:plane:)).

## Was der neue Symbolprüfer bereits belegt

```sh
python3 tools/graphics_interfaces.py --consumer "/Selected/LunarBridge.kext/Contents/MacOS/LunarBridge" --out reports/interfaces.json
python3 tools/graphics_interfaces.py --consumer "/Selected/Consumer" --provider "/Selected/ExtractedProvider" --out reports/interfaces.json
python3 tools/graphics_interfaces.py --consumer "/Selected/Consumer" --export-list "/Selected/IOKit.exports" --export-list "/Selected/IOKit.x86_64.exports" --out reports/interfaces.json
```

Der Prüfer läuft auch unter Windows, da er nur ausdrücklich ausgewählte lokale
Dateien liest. Er untersucht Thin-/Fat-Mach-O, nlist-Symboltabellen sowie direkte
Export-Tries. Reexports/Aliase werden nicht als aufgelöste Provider ausgegeben.
Nur passende x86_64-Slices werden für den Zielvergleich verwendet. Quelllisten
werden in einem getrennten Feld verglichen; sie ersetzen keine Binärexporte.

Er gibt feste Interface-Namen, Zählwerte und Dateihashes aus. Dateipfade,
beliebige Symbolnamen, fremde Appnamen und vollständige Bibliotheks-/Metadaten
erscheinen nicht. Maximal 16 Auswahldateien, 64 MiB pro Binärdatei und 128 MiB
insgesamt begrenzen Eingaben. Symbole, Stringtabellen, Trie-Knoten, Namenslängen
und deren kumulierter Umfang haben zusätzliche Grenzen. Spezialdateien werden
vor dem Öffnen und erneut per fstat abgelehnt. Die einzige beabsichtigte
Schreibänderung ist der ausdrücklich gewählte, atomar ersetzte JSON-Bericht.

Kernel-Filesets und dyld-Shared-Caches werden nicht als gewöhnliche Einzeldatei
interpretiert. Dafür sind eine gesonderte Extraktion und deren Provenienz
erforderlich. Chained-Import-Tabellen, dyld-Bind-Opcodes und Objective-C-
Selektoren werden nicht dekodiert. Fehlende Symbole bedeuten ausschließlich
"in den untersuchten Tabellen nicht beobachtet". Ein Kext braucht selbst keine
benutzermodalen Metal-C-Imports; deren Fehlen beweist für sich allein keine
fehlende Metal-Implementierung.

Lokale Prüfung echter vorhandener CI-Binärdateien, ohne Ausführung:

| Datei/Quellstand | SHA256 | Tatsächliches Symbolergebnis |
| --- | --- | --- |
| LunarBridge Kext, cb47a2de119440731a44a14105df4a4192613123 | `8c81f17be10d9e32a87de31f83f66b0bec873623b5a8fc4c8da9ae283d1e47b7` | x86_64, MH_KEXT_BUNDLE, 342 Imports; 145 IOService, 37 IOUserClient, 1 IOBufferMemoryDescriptor. Keine beobachteten IOFramebuffer-/IOAccel-/Mapper-/DMA-Anschlüsse. Dieses Artefakt liegt vor dem neuen DMA-Anschluss. |
| hdr-readback | `34099fc8758290d800c9cc55cd5795d729c919da52ee8a740c062ca149c3f110` | x86_64, MH_EXECUTE, 163 Imports, darunter MTLCopyAllDevices. |
| lb-camera-probe | `17ae15df607034dd4e4ff5f22068be94f47807fb849e58852a50c4998e372e93` | x86_64, MH_EXECUTE, 120 Imports. Kein Metal-C-Import in der untersuchten Tabelle. |

47 reservierte IOService- und 16 reservierte IOUserClient-Imports des genannten
Kexts wurden in den beiden XNU-Quelllisten nicht beobachtet. Das ist kein
festgestellter Ladefehler: Apples kxld passt geerbte Vtable-Einträge zur
Versionskompatibilität an. Slot-Zuordnung und tatsächliche native Kextlink-
Abnahme müssen deshalb geprüft werden; manuelle Null-Stubs würden keinen
korrekten Ersatz schaffen.
[Apple XNU: Vtable-Patching](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/libkern/kxld/kxld_vtable.c).

24 neue Grenz-/Privacytests und die vorhandenen 30 Softwaretests bestehen
lokal unter Windows. Die erweiterte Mac-CI kompiliert eine eigene kleine
Metal-/IOSurface-/IOKit-Importdatei und prüft das erzeugte Mach-O, ohne das
Programm zu starten. Der erfolgreiche Online-Lauf des bisherigen 30-Test-
Stands qualifiziert diese neue Erweiterung noch nicht. Das neue CI-Ergebnis
und die gesamte Samsung-Geräteprobe sind bis zu deren Ausführung offen.

## Lade- und Secure-Boot-Voraussetzungen vor Hardwareausführung

Ein erfolgreich mit `-undefined dynamic_lookup` gelinkter Kext ist keine
Ladeabnahme. Die tatsächlichen Provider, Kext-Abhängigkeiten, Intel-Vtables,
Signatur-/Freigabepolicy und der verwendete Kernel-Collection-Pfad müssen
zusammen passen. SIP- und Gatekeeper-Status allein beantworten das nicht.
Apples Vorgaben zur Reduced Security im Apple-Silicon-Startvolume gelten nicht
als Anleitung für diesen Intel-Samsung-Rechner.
[Apple: Kext-/Systemextension-Policy](https://support.apple.com/guide/deployment/system-extensions-in-macos-depa5fb8376f/web).

Firmware UEFI Secure Boot bleibt ein eigenes Pflichtkriterium. Die komplette
OpenCore-/EFI-Vertrauenskette und Apples SecureBootModel samt Kextakzeptanz
müssen separat belegt werden. Das bisher unsignierte Diagnose-Artefakt belegt
diesen fertigen Zustand nicht. Der Softwareprüfer setzt keine Policy um und
empfiehlt keine Deaktivierung von Firmware Secure Boot.
[OpenCore: UEFI Secure Boot und SecureBootModel](https://github.com/acidanthera/OpenCorePkg/blob/master/Docs/Configuration.tex).

Die nächsten Portierungspunkte sind damit konkret: den neuen DMA-Kext gegen
die veröffentlichten und anschließend realen Intel-Tahoe-Provider prüfen;
native Lade-/Mapper-Lebensdauer belegen; die versionsgenauen IOAccel-
UserClient-/Surface-Verträge erheben; erst danach Metal-Geräteauswahl,
Shaderpfad und Desktop-Übergabe implementieren und ausführen. Dieses Modul
liefert die Prüfwerkzeuge und den abgegrenzten Anschlussvertrag; die genannten
GPU-Funktionen sind noch nicht implementiert oder am Samsung verifiziert.
