# Local Connection Modes

Goal: support local REMKO operation without making users understand REMKO's
transport details during setup. The implementation may have several technical
paths, but the Home Assistant onboarding should guide users through checks and
show the detected result.

## Known Architectures

### Cloud

The integration logs in to SmartWeb, resolves the device SID/SK, connects to
REMKO's MQTT-over-WebSocket broker, and uses the normal SmartWeb topics:

- status/control frames: `V04P27/<SID>/ESP` and `V04P27/<SID>/RESP`
- value reads/writes: `V04P27/<SID>/CLIENT2HOST` and `.../HOST2CLIENT`

This is the production path from `main`. Feature branches must keep this path
behaviour-compatible unless a deliberate cloud fix is made.

### Local Portal Broker

Some WiFi sticks do not expose MQTT on their own IP. They connect outbound to
the configured SmartWeb broker instead. Local operation is possible by
redirecting only that stick to a local Mosquitto listener.

Observed with MXW WiFi sticks:

- stick announces on `V04P27/SMT.../HOST2PORTAL`
- local portal answers `V04P27/SMT.../PORTAL2HOST` with `{"WSID": ""}`
- actual control still uses the SID path `V04P27/<SID>/ESP` and `/RESP`

This mode needs broker/listener diagnostics because failures can look like HA
state changes while the stick is not subscribed to the command topic.

### Local Device MQTT

Some SmartControl/SmartCom devices expose a local MQTT path directly or via a
Mosquitto bridge to the device IP. `Altrec/remko_mqtt-ha` is an example of this
architecture.

Known shape from that project and issue reports:

- user config points at a local MQTT node/prefix
- data topic: `<node>/SMTID/HOST2CLIENT`
- command topic: `<node>/SMTID/CLIENT2HOST`
- `SMTID` can be a literal topic segment; real IDs may be in the payload
- credentials may come from the local SmartControl web UI, e.g. `smt.min.js`

This should be implemented as another transport adapter, not as separate HA
entities or duplicated profile logic.

Initial support in `feature/local-portal-support`:

- options include an explicit `local_mqtt_mode`
- automatic discovery can classify `HOST2PORTAL` as `local_portal_broker`
- automatic discovery can classify `HOST2CLIENT`/`CLIENT2HOST` topics as
  `local_device_mqtt`
- `local_device_mqtt` uses value-based `CLIENT2HOST` writes directly instead
  of forcing AC C0/ESP writes
- `local_device_mqtt` reads values before trying the cloud-style ESP status path

This still needs real hardware testing because topic prefixes and payload fields
can differ between SmartControl installations.

## Product Onboarding

The UI should avoid protocol names as the first user-facing choice. A good flow:

1. Ask for the normal SmartWeb account first.
2. Show discovered devices.
3. Offer connection preference:
   - `Use REMKO cloud`
   - `Try local connection`
4. If local is selected, ask for the minimum concrete input:
   - device IP or local broker host
   - port, with `1883` as the direct/bridge default and `8883` as a portal-listener hint
   - username/password only if required
5. Run probes and show a clear result:
   - Cloud only
   - Local portal broker detected
   - Local device MQTT detected
   - Local MQTT reachable but no REMKO topics seen
   - MQTT auth/ACL failed
6. Create the entry only after the user sees the detected mode and guidance.

Users should not have to choose between `HOST2PORTAL`, `CLIENT2HOST`, SID, or
SMT topics manually in the common path. Manual topic overrides can be advanced
options later.

## Probe Checklist

For a local target, probe in this order:

1. TCP connect to the configured host/port.
2. MQTT CONNACK result and auth status.
3. Subscribe/read-only probe for direct/bridge topics:
   - `+/SMTID/HOST2CLIENT`
   - `V04P28/SMTID/HOST2CLIENT`
   - `V04P27/SMTID/HOST2CLIENT`
   - optional user-provided prefix
4. Subscribe/read-only probe for portal-broker topics:
   - `V04P27/+/HOST2PORTAL`
   - `V04P27/+/CLIENT2HOST`
5. If portal-broker mode is detected, resolve the SmartWeb SID command topic
   from the cloud account and subscribe to `/ESP` and `/RESP`.
6. Never send a control command during onboarding probes unless the user
   explicitly starts a test command.

## Implementation Direction

Keep a single semantic write/read layer:

```text
HA entity -> profile write/read plan -> transport adapter
```

The transport adapter should own only:

- broker connection setup
- topic naming
- `CLIENT_ID` style
- local portal heartbeat replies
- diagnostics for freshness, auth, subscriptions, and readback

Profiles should not need to know whether the device is cloud, local portal
broker, or local device MQTT.

## Open Questions

- There is no reliable public device-model matrix yet. Hardware module and
  firmware seem more important than REMKO product family.
- RBW/DHW users may be good testers for non-MXW cloud contracts, but local MQTT
  support depends on their actual communication module.
- Direct local MQTT needs a test fixture or user-provided redacted captures
  before it can be considered supported.
