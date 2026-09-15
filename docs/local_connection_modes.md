# Local Connection Modes

Goal: support local REMKO operation without making users understand REMKO's
transport details during setup. The implementation may have several technical
paths, but the Home Assistant onboarding should start from the known cloud
device, guide the user through one local candidate at a time, and show the
detected result with actionable checks.

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

Initial technical support in `feature/local-portal-support`:

- options include an explicit `local_mqtt_mode`
- `_mqtt.probe_local_mqtt()` returns a structured read-only probe result for a
  user-selected host/broker
- automatic discovery can classify `HOST2PORTAL` as `local_portal_broker`
- automatic discovery can classify `HOST2CLIENT`/`CLIENT2HOST` topics as
  `local_device_mqtt`
- `local_device_mqtt` uses value-based `CLIENT2HOST` writes directly instead
  of forcing AC C0/ESP writes
- `local_device_mqtt` reads values before trying the cloud-style ESP status path

This still needs real hardware testing because topic prefixes and payload fields
can differ between SmartControl installations.

## Product Onboarding

The UI should avoid protocol names as the first user-facing choice. Local setup
must be anchored to the cloud-discovered device instead of trying to infer a
device from random MQTT traffic. A good flow:

1. Ask for the normal SmartWeb account first.
2. Show the cloud-discovered devices and let the user choose the exact device.
3. Store the cloud identity (`device_path`, SID/SK metadata when available,
   profile, current cloud write/read behaviour). This remains the baseline and
   fallback.
4. Offer connection preference for that selected device:
   - `Use REMKO cloud`
   - `Try local connection`
5. Help the user find a candidate local target:
   - show guidance that REMKO sticks often announce generic Espressif hostnames
     such as `espressif`; multiple sticks may use the same hostname, so this is
     only a candidate source, not a unique device match
   - optionally suggest candidates from infrastructure-neutral sources that are
     available in the running HA environment:
     - the system resolver search domain (`espressif`, `espressif.local`)
     - the default gateway/router DNS server, when it can be inferred
     - Home Assistant network discovery or integrations that expose network
       device metadata
     - the ARP/neighbor table, but only after a MAC is already known
   - present these as suggestions for the selected cloud device, not as an
     automatic mapping; if no candidate is known, ask the user for the device
     IP address
6. Probe the candidate IP as a direct local MQTT device first:
   - read the local ARP/neighbor cache for the candidate IP; if it yields a
     MAC address, derive the expected stick base topic `V04P27/SMT<MAC>`
     and show it as supporting evidence for the chosen candidate
   - TCP connect to `1883` and optionally `8883`
   - MQTT CONNACK/auth result
   - read-only subscribe for likely SmartControl topics such as
     `V04P28/SMTID/HOST2CLIENT`, `V04P27/SMTID/HOST2CLIENT`, and
     `+/SMTID/HOST2CLIENT`
   - if values arrive, classify as `local_device_mqtt` and use the direct
     `CLIENT2HOST`/`HOST2CLIENT` transport
7. If no MQTT service is reachable on the device IP, explain the redirected
   portal-broker option instead of silently failing:
   - the stick likely connects outbound to REMKO's broker
   - the user needs a local broker/listener and a DNS rewrite for this one stick
   - Home Assistant must be able to connect to that local broker
   - for AdGuard Home, prefer per-client rewrite rules so only the selected
     stick IP is redirected:
     `||smartweb.remko.media^$client=<stick-ip>,dnsrewrite=<broker-ip>`
8. Probe the local broker/listener for the redirected-stick path:
   - TCP connect to the user-provided local broker host/port
   - MQTT CONNACK/auth result for the Home Assistant-side account
   - read-only subscribe for `V04P27/+/HOST2PORTAL`
   - once the user has redirected the selected stick, verify whether the
     `HOST2PORTAL` topic matches the expected `V04P27/SMT<MAC>` from the chosen
     IP; if another `SMT<MAC>` appears, warn the user that the DNS redirect may
     point to a different stick
   - resolve the SID command topic from the cloud baseline and require local
     readback before considering the mapping healthy
9. Show a clear result before switching the entry:
   - Cloud only
   - Direct local MQTT detected
   - Redirected local portal broker detected
   - Local MQTT reachable but no REMKO topics seen
   - MQTT auth/ACL failed
   - TCP connect failed
   - Waiting for redirected stick heartbeat
10. Create or update the entry only after the user sees the detected mode and
    guidance. Keep cloud as the fallback until local readback is observed.

Users should not have to choose between `HOST2PORTAL`, `CLIENT2HOST`, SID, or
SMT topics manually in the common path. Manual topic overrides can be advanced
options later.

### Why Topic-Only Auto-Detection Is Not Enough

Seeing `HOST2PORTAL` is already a consequence of a successful DNS redirect and
stick connection to a local broker. From Home Assistant's perspective there is
no DNS rewrite event to detect; HA only connects to the broker host configured
by the user. Therefore automatic mode should mean "run guided probes against the
user-selected local target" rather than "listen broadly and guess the setup".

Likewise, hostname hints such as `espressif` are not tied to one router vendor.
They are usually the hostname sent by the ESP-based stick and may be surfaced by
DHCP, local DNS, mDNS, or a router integration. Since several sticks can publish
the same hostname, these hints should feed a selectable candidate list. They
must not silently decide which cloud device maps to which IP.

This is especially important when migrating one stick at a time. Other sticks
may still be cloud-only, so Home Assistant cannot prove every candidate by
trying all channels. The user-selected IP plus ARP MAC gives an expected
`SMT<MAC>` topic; the first redirected `HOST2PORTAL` heartbeat is then used as
a consistency check. If it does not match the expected MAC/topic, show a
"possible mismatch" warning and keep the cloud fallback.

For direct device MQTT, the meaningful probe is the device IP itself. For
redirected portal-broker mode, the meaningful probe is the local broker plus a
stick heartbeat after the user has configured DNS.

## Probe Checklist

For a local target, probe in this order:

1. Start from a cloud-resolved device and retain cloud as fallback.
2. If the user provides a device IP, TCP probe direct MQTT ports first.
3. Read ARP/neighbor metadata for that selected IP. If a MAC is available, derive
   `V04P27/SMT<MAC>` as the expected redirected-stick base topic. This can
   validate later `HOST2PORTAL` traffic, but it still does not prove which cloud
   device it is until SID/heartbeat/readback match.
4. MQTT CONNACK result and auth status.
5. Subscribe/read-only probe for direct/bridge topics:
   - `+/SMTID/HOST2CLIENT`
   - `V04P28/SMTID/HOST2CLIENT`
   - `V04P27/SMTID/HOST2CLIENT`
   - optional user-provided prefix
6. If direct device MQTT is not reachable, ask for or validate the local broker
   used for DNS-redirect mode.
7. Subscribe/read-only probe for portal-broker topics:
   - `V04P27/+/HOST2PORTAL`
   - `V04P27/+/CLIENT2HOST`
8. If portal-broker mode is detected, resolve the SmartWeb SID command topic
   from the cloud account and subscribe to `/ESP` and `/RESP`. Compare the
   observed `HOST2PORTAL` topic with the expected `SMT<MAC>` topic from the
   selected IP and warn on mismatch.
9. Never send a control command during onboarding probes unless the user
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
