# REMKO Model Catalog Notes

`docs/remko_model_catalog.csv` is a curated reference list generated from an
external research spreadsheet. It is intentionally stored as CSV instead of the
original XLSX so changes stay reviewable in git.

The catalog is not a support guarantee. Use it as input for triage, issue
labels, README grouping, and future profile matching.

## Field Meanings

- `Cloud_Betrieb = Ja`: the referenced REMKO product page or evidence text
  explicitly mentions internet, WiFi, Smart-Web, cloud, or similar remote
  operation for that model family.
- `Cloud_Betrieb = nicht belegt`: the checked source did not explicitly mention
  cloud or Smart-Web operation. This is not a technical exclusion.
- `Cloud_Art`: the kind of cloud/WiFi wording found in the source, for example
  `optional WiFi`, `WiFi ready`, `Smart-Web`, or `Internet serienmäßig`.
- `Cloud_Evidenz`: short evidence summary from the source research.
- `Quelle`: source URL used for the catalog row.

## Support Interpretation

For split and multi-split AC systems, the indoor unit family is usually more
important for this integration than the outdoor unit. A multi-split outdoor unit
such as `MVT DC` can indicate that WiFi is available for compatible indoor
units, but the actual SmartWeb profile should be chosen from the indoor unit
series, for example `MXW`, `MXD`, `MXT`, `ATY`, or `ATY Deko`.

For heat pumps, product-family names are not enough by themselves. The
transport can be REMKO cloud, redirected WiFi stick, or direct SmartControl MQTT,
and firmware can affect topic shape and register IDs. Keep WKF/WPM/WSP-style
profiles conservative and read-only/diagnostic until logs confirm the mapping.

## Current Architectural Takeaways

- Keep runtime support in code profiles, not in the catalog. The catalog can
  suggest candidate profile matching, but it should not decide write support.
- Prefer grouped README rows over one row per article number.
- Treat `Cloud_Betrieb = Ja` as onboarding guidance: the model family is worth
  trying with a SmartWeb account or local setup.
- Treat `Cloud_Betrieb = nicht belegt` as unknown: ask for logs or diagnostics
  rather than rejecting the device.
