# Quick Deployment: Branch-Wechsel fuer Home Assistant

Ziel: `custom_components/remko_smartweb` schnell und reproduzierbar zwischen Git-Branches in der laufenden Home-Assistant-Installation wechseln.

## Ablauf

1. Lokal den Zielbranch vorbereiten.

```bash
cd /home/node/.openclaw/workspace/.tmp/remko-smartweb-ha
git fetch origin
git checkout <branch>
git pull --ff-only origin <branch>
```

2. Vor dem Deployment validieren.

```bash
python3 -m py_compile custom_components/remko_smartweb/api.py
python3 -m unittest discover -s tests -v
```

3. Deployment nur mit Backup ausserhalb von `custom_components`.

```bash
TS="$(date -u +%Y%m%dT%H%M%SZ)"
docker exec homeassistant mkdir -p /config/openclaw_component_backups
docker exec homeassistant cp -a \
  /config/custom_components/remko_smartweb \
  /config/openclaw_component_backups/remko_smartweb_before-${branch}-${TS}
```

4. Komponente exakt ersetzen.

```bash
tar --exclude='__pycache__' --exclude='*.pyc' \
  -cf /tmp/remko_smartweb.tar -C custom_components remko_smartweb
docker exec homeassistant mv \
  /config/custom_components/remko_smartweb \
  /config/openclaw_component_backups/remko_smartweb_previous-dir-${TS}
docker cp /tmp/remko_smartweb.tar homeassistant:/config/custom_components/
```

5. Syntax im Container pruefen und Home Assistant neu starten.

```bash
docker exec homeassistant python3 -m py_compile \
  /config/custom_components/remko_smartweb/api.py
docker restart homeassistant
```

6. Verifikation.

```bash
docker logs --tail=200 homeassistant 2>&1 \
  | grep -iE 'remko|smartweb|error|warning|traceback'
```

Pruefen:

- Home Assistant API/UI ist wieder erreichbar.
- Remko-Entities sind vorhanden.
- Keine neuen Import-/Traceback-Fehler.
- Bei Branchwechseln mit Python-Code immer Neustart, kein reiner Integration-Reload.

## Wichtige Regel

Keine Backup-Ordner unter `/config/custom_components` liegen lassen. Home Assistant versucht dort jeden Ordner als Custom Integration zu importieren.
