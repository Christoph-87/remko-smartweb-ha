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

## How To Learn More

The catalog can only tell us where REMKO publicly hints at WiFi, Smart-Web, or
cloud capability. To decide which integration path a real installation uses, we
need technical evidence from one of these sources:

1. **Cloud device metadata** from the normal SmartWeb login flow: device name,
   portal type, SID/SK topic, `TYPE`, `DEV`, and available payloads.
2. **Debug logs from this integration** with diagnostics enabled. These show
   whether the device returns C0/ESP status, SmartWeb `values`, or another
   payload shape.
3. **Local MQTT probe results** from a candidate local IP or broker:
   - direct device MQTT: `HOST2CLIENT` / `CLIENT2HOST` topics such as
     `V04P28/SMTID/...`
   - redirected stick: `HOST2PORTAL` from `V04P27/SMT...` after DNS redirect
4. **Device web assets**, if reachable locally. Some SmartControl devices expose
   `smt.min.js`, which can reveal the direct MQTT password used by
   SmartControl-style MQTT.
5. **Known-register evidence** from community field reports. Treat this as
   heat-pump/direct-MQTT evidence unless a matching AC/RBW/LTE device log proves
   the same transport.

Official REMKO product pages are useful for onboarding hints, but they do not
prove which transport the Home Assistant integration can use.

## Current Architectural Takeaways

- Keep runtime support in code profiles, not in the catalog. The catalog can
  suggest candidate profile matching, but it should not decide write support.
- Prefer grouped README rows over one row per article number.
- Treat `Cloud_Betrieb = Ja` as onboarding guidance: the model family is worth
  trying with a SmartWeb account or local setup.
- Treat `Cloud_Betrieb = nicht belegt` as unknown: ask for logs or diagnostics
  rather than rejecting the device.
