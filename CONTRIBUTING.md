# Contributing to REMKO SmartWeb for Home Assistant

Thanks for helping improve this integration. Device reports are especially
valuable because REMKO model names, communication modules, and firmware versions
do not always map cleanly to one protocol.

## Good First Contributions

- Confirm whether a model works through the REMKO SmartWeb cloud path.
- Share redacted diagnostics for an unsupported or unknown device.
- Improve documentation for a tested device family.
- Add read-only sensors when the payload meaning is clear.
- Add tests for an existing profile or transport behavior.

Please be careful with write support. New writes should stay disabled or
diagnostic-only until the command payload, readback, and failure behavior are
understood.

## Reporting a Device

Open an issue and include:

- REMKO model name and, for split or multi-split systems, the indoor unit series.
- Whether the device works in the REMKO app or SmartWeb portal.
- Integration version and Home Assistant version.
- Diagnostics sensor attributes such as `detected_profile`, `portal_type`, and
  `portal_dev`.
- Redacted debug logs around startup and, if relevant, one controlled setting
  change made in the REMKO app.
- For local MQTT tests, the detected mode: cloud, redirected WiFi stick, or
  direct device MQTT / SmartControl.

Remove email addresses, passwords, cookies, session IDs, access keys, exact
account details, and private network details before posting logs publicly.

## Documentation Data

Curated Markdown and CSV files in `docs/` can be committed when they are useful
for users or contributors. Raw research files should not be committed, including
spreadsheets, packet captures, HAR exports, debug logs, and local-only runbooks.

The model catalog is evidence for triage and grouping, not a support guarantee.
Runtime support belongs in code profiles and tests.

## Checks Before a Pull Request

Run the local checks that match your change:

```bash
python -m unittest discover -s tests -v
python -m py_compile custom_components/remko_smartweb/api.py
```

For documentation-only changes, at least run:

```bash
git diff --check
```

GitHub Actions also run validation and hassfest for pull requests.

## Pull Request Guidelines

- Keep changes focused on one device family, transport, or documentation topic.
- Prefer profile-specific behavior over broad global mappings.
- Add tests for parser changes, write paths, and profile-specific query IDs.
- Update the README or docs when user-visible support changes.
- Explain what hardware, firmware, or logs were used for validation.
