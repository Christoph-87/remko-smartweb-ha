# WPM/WKF register mapping assistant

Version 0.5.1 adds a read-only mapping assistant for WPM/WKF devices. It helps
identify unknown SmartWeb value IDs without sending speculative writes to the
heat pump.

## Capture one setting

1. Wait until the REMKO communication-status sensor reports `ready` and values
   are updating.
2. On the device page, press the diagnostic button **Start register mapping
   capture**.
3. Change exactly one setting in the official REMKO app or on the controller.
4. Open the diagnostic sensor **Register mapping capture** and inspect its
   `observations` attribute. Each observation contains a timestamp and the
   changed value IDs with `old` and `new` raw values.
5. Restore the setting to its original value. A matching reverse transition is
   much stronger evidence than a single change.
6. Repeat the capture separately for each setting. Do not combine unrelated
   changes in one observation.

The capture stays in memory only. Starting a new capture clears the previous
result, and restarting Home Assistant removes it. At most 20 observations and
50 changes per observation are retained.

## Interpreting the result

- Prefer IDs that change in both directions exactly when the selected setting
  changes.
- Ignore temperatures, counters, and operating values that continue changing
  independently.
- Repeat the same test at least once before assigning a meaning to an ID.
- An observed correlation proves a read mapping, not necessarily that writing
  the same ID is safe. Write support needs separate device readback evidence.

## WKF 120 firmware 4.26 status

From the 35 IDs reported in issue #13:

- Already interpreted by the WPM profile: `1082`, `1946`, `1951`, `5001`,
  `5034`, `5039`, `5055`.
- General portal/device metadata in the REMKO JavaScript, not confirmed WPM
  controls: `3950`, `5074`, `5106`, `5198`.
- `1088` belongs to the separate WSP profile and is not treated as a WKF/WPM
  mapping.
- `1137` is only a commented/unconfirmed candidate in the REMKO JavaScript.
- Still unidentified: `1014`, `1220`, `1249`, `1726`, `1727`, `1935`, `1937`,
  `1938`, `1967`, `1976`, `1978`, `1979`, `5029`, `5109`, `5148`, `5182`,
  `5229`, `5230`, `5240`, `5292`, `5763`, `5870`.

When reporting a mapping, include the device model and firmware, the setting
changed, both forward and reverse transitions, and approximate timestamps.
Remove credentials and personal data before sharing diagnostics.
