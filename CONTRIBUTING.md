# 🤝 Contributing to REMKO SmartWeb for Home Assistant

Thanks for helping improve the integration. Device reports are especially
valuable because REMKO model names, communication modules, and firmware versions
do not always map cleanly to one protocol.

## 🌱 Ways to Contribute

- Confirm a device model and its connection path.
- Share redacted diagnostics for an unsupported device.
- Improve documentation for tested hardware.
- Add read-only sensors when the payload meaning is known.
- Add tests for an existing device profile or transport.

Write support needs extra care. Do not enable a new write path until its command
payload, device readback, and failure behavior are understood and tested.

## 🐛 Reporting a Bug

[Open a GitHub issue](https://github.com/Christoph-87/remko-smartweb-ha/issues/new/choose)
and include:

- integration and Home Assistant versions
- exact REMKO model and communication module, if known
- connection mode: REMKO Cloud, redirected WiFi stick, or direct device MQTT
- expected and actual behavior
- redacted diagnostics and relevant debug-log lines
- steps that reproduce the problem

Remove email addresses, passwords, cookies, session IDs, access keys, account
details, and private network information before posting.

## 🧩 Reporting a New Device

Use the **New device support** issue template and include:

- the model name shown by REMKO
- for split or multi-split systems, the indoor-unit series
- whether it works in the REMKO app or SmartWeb portal
- Diagnostics sensor attributes such as `detected_profile`, `portal_type`, and
  `portal_dev`
- a redacted debug log around startup
- screenshots of the settings available in the REMKO app

When investigating writable values, change only one setting at a time in the
REMKO app and note what changed and when.

## 💻 Development Workflow

1. Fork the repository and create a focused branch from `main`.
2. Make the change and add tests for parser, profile, or write-path behavior.
3. Update user documentation when behavior or device support changes.
4. Run the local checks.
5. Open a pull request and explain which hardware, firmware, or logs were used.

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q custom_components/remko_smartweb
git diff --check
```

GitHub Actions also run unit tests, HACS validation, and hassfest.

## ✅ Pull Request Checklist

- Keep the change focused on one device family, transport, or documentation
  topic.
- Prefer profile-specific behavior over broad global mappings.
- Include tests for parsing, writes, and readback where applicable.
- Keep new or uncertain writes disabled until safely verified.
- Do not include credentials, personal data, raw packet captures, or debug logs.
- Update the README or local MQTT guide for user-visible changes.

## 📝 Documentation

Keep public documentation concise and task-oriented. Do not commit raw research
files, spreadsheets, packet captures, HAR exports, debug logs, or local-only
runbooks.

## 💡 Proposing a Feature

[Open an issue](https://github.com/Christoph-87/remko-smartweb-ha/issues/new/choose)
describing the use case, affected hardware, and expected Home Assistant behavior.
Protocol observations or redacted diagnostics are more useful than a proposed UI
alone.
