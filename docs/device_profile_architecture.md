# Device Profile Architecture

This integration currently uses Python device profiles as the main extension
point. A profile owns the device-family behavior:

- model/name matching
- supported transports
- value query IDs
- value parsing
- write encoding
- entity descriptions
- firmware or family quirks

That is a good fit for REMKO because the same visible device family can differ
by transport and firmware. Examples:

- Split and multi-split AC support depends mostly on the indoor unit profile,
  not just the outdoor unit.
- WKF/WPM and WSP heat pumps can expose similar values through different IDs,
  for example `1951` vs `1088` for the heat/cool mode candidate.
- Local operation can be a redirected WiFi stick or direct SmartControl MQTT.
  Those are transport adapters, not separate Home Assistant device models.

## EVCC-Style Templates

EVCC templates are strong when many devices share a generic communication
backend and the variation is mostly declarative: host, credentials, protocol,
registers, topics, and metadata. That is useful for a large device catalog and
for generated documentation.

For this integration, copying that model completely would be premature:

- REMKO payloads are not just register lists; several families need custom
  parsing and write confirmation behavior.
- Home Assistant entities need profile-specific behavior, not only raw value
  reads.
- Local MQTT discovery and cloud fallback are stateful runtime behavior.

What is worth adopting:

- Keep a catalog-like data file for model grouping and onboarding hints.
- Add declarative pieces inside profiles where they fit, especially query IDs,
  entity descriptions, and straightforward value mappings.
- Avoid putting safety-relevant write behavior into raw YAML until the
  confirmation semantics are clear.

## OpenEMS-Style Components

OpenEMS is closer to an industrial component model: devices expose typed
channels, components implement shared natures/interfaces, and controllers work
against those stable abstractions.

That is a useful design direction conceptually, but too heavy for this Home
Assistant integration. The practical version here is:

- Profiles expose a stable internal status dictionary.
- Transports provide cloud/local/direct MQTT access without duplicating profile
  logic.
- Entity platforms consume the profile status/write contracts.
- Future heat-pump support can split into more specific classes such as
  `WkfDeviceProfile`, `WspDeviceProfile`, `WkmDeviceProfile`, and shared
  heat-pump base helpers.

## Decision

Stay on the current profile-based path.

Do not switch wholesale to EVCC-style external templates yet. Instead, evolve
profiles toward a hybrid:

- Python classes for behavior, safety, discovery, parsing, and writes.
- Declarative attributes for model aliases, query IDs, entity metadata, and
  simple register/value mappings.
- A separate catalog CSV for documentation and onboarding hints.

This keeps the code extensible without pretending the current REMKO protocol
surface is purely declarative.

## References

- EVCC template documentation:
  <https://github.com/evcc-io/evcc/blob/master/templates/README.md>
- EVCC plugin documentation:
  <https://docs.evcc.io/en/reference/plugins/>
- OpenEMS Edge architecture:
  <https://openems.github.io/openems.io/openems/latest/edge/architecture.html>
- OpenEMS Edge configuration model:
  <https://openems.github.io/openems.io/openems/latest/edge/configuration.html>
