# Local MQTT Setup

Local MQTT is optional and experimental. Configure one device at a time and
confirm reliable status updates before testing controls. If you are unsure which
mode applies, keep using **REMKO Cloud**.

## Choose the Correct Mode

There are two hardware cases:

| Your communication module | Integration mode |
|---------------------------|------------------|
| Connects to REMKO Cloud | Keep **REMKO Cloud**, or intentionally redirect this stick to a local broker with **Redirected WiFi stick / local portal broker** |
| Exposes MQTT on its own IP or through SmartControl | Use **Direct device MQTT / SmartControl bridge** |

Do not configure a DNS redirect for a device that already exposes local MQTT.

## Direct Device MQTT

Use this mode only when the stick/device provides an MQTT service on the local
network.

1. Open the REMKO SmartWeb integration options for the device.
2. Under **Local connection**, select
   **Direct device MQTT / SmartControl bridge**.
3. Enter the stick/device MQTT host, port, and credentials.
4. Save and check the communication-status sensor for fresh local data.
5. Verify status updates before testing a control.

No DNS rewrite or separate MQTT broker is required for this mode.

## Redirect a Cloud-Connected WiFi Stick

This setup replaces the stick's connection to REMKO's broker with your own
broker. Home Assistant then communicates with the stick locally.

Without the optional app bridge, the REMKO app cannot reach the redirected
stick. Enabling **Bridge REMKO app commands through Home Assistant** lets Home
Assistant relay app commands between REMKO Cloud and the local broker. The
bridge is experimental and still requires internet access and valid REMKO
credentials.

### Requirements

- a device that already works through REMKO Cloud
- the selected WiFi stick's IP address
- a local MQTT broker reachable from Home Assistant
- a client-specific DNS rewrite for that stick
- a TLS certificate accepted by the stick for `smartweb.remko.media`

Keep the cloud setup working until local status readback is confirmed.

### Broker Listeners

Use separate broker listeners for Home Assistant and the redirected stick:

| Listener | Typical port | Authentication |
|----------|--------------|----------------|
| Home Assistant | `1883` | Username/password recommended |
| Redirected stick | `8883` | Must match the stick's TLS and authentication behavior |

Example Mosquitto structure:

```conf
per_listener_settings true

listener 1883
allow_anonymous false
password_file /mosquitto/config/passwords

listener 8883
cafile /mosquitto/config/ca.crt
certfile /mosquitto/config/smartweb.remko.media.crt
keyfile /mosquitto/config/smartweb.remko.media.key
allow_anonymous true
```

Adapt paths, credentials, ACLs, and certificate handling to your broker. This is
not a complete drop-in configuration.

The certificate presented on the stick-facing listener needs
`smartweb.remko.media` as its CN or SAN. The integration does not create or
manage broker certificates.

### DNS Redirect

Redirect only the selected stick. Home Assistant and other clients must still
be able to reach the real REMKO endpoint.

Example client-scoped AdGuard Home rule:

```text
||smartweb.remko.media^$client=<stick-ip>,dnsrewrite=<broker-ip>
```

Replace `<stick-ip>` and `<broker-ip>` with the corresponding local addresses.
Equivalent client-specific rules in other DNS servers are fine. Avoid a global
rewrite.

### Integration Setup

1. Keep or add the device through the normal REMKO Cloud setup.
2. Open its integration options and go to **Local connection**.
3. Select **Redirected WiFi stick / local portal broker**.
4. Enter the **Stick IP candidate**. It identifies the expected stick; it is not
   the broker address.
5. Enable the REMKO app bridge only if you need the original app after the
   redirect.
6. Enter the local broker host, Home Assistant listener port, and credentials.
7. Save the options, apply the DNS rule, and reconnect the stick.

## Verify Before Using Controls

For either local mode:

1. Confirm that the integration's communication-status sensor reports a local
   MQTT connection.
2. Confirm that status values update from the device.
3. Change one harmless setting and wait for matching device readback.
4. Configure another device only after the first one remains stable.

For a redirected stick, also confirm:

- the stick resolves `smartweb.remko.media` to the local broker
- the broker sees the stick on the stick-facing listener
- `V04P27/SMT.../HOST2PORTAL` traffic arrives

For direct device MQTT, typical data and command topics end in
`HOST2CLIENT` and `CLIENT2HOST`.

## Troubleshooting

| Symptom | Check |
|---------|-------|
| No local status | Host, port, credentials, ACLs, and communication-status diagnostics |
| Redirected stick never connects | Client-specific DNS rule, stick IP, port `8883`, and broker logs |
| TLS connection fails | Certificate CN/SAN must include `smartweb.remko.media` |
| Home Assistant connects but the stick does not react | `HOST2PORTAL` traffic and the detected stick/topic mapping |
| Another stick appears | The DNS rule or broker discovery is not limited to the intended stick |
| REMKO app stops working after redirect | This is expected without the optional app bridge |

To return a redirected stick to REMKO Cloud, remove its DNS rule, select
**REMKO Cloud** in the integration options, and reconnect the stick.

## Reporting a Problem

Open an issue and include:

- device and communication-module model, if known
- selected local mode
- broker type and listener ports
- whether local MQTT traffic is visible
- redacted integration diagnostics and debug logs

Remove credentials, cookies, session IDs, access keys, public IP addresses, and
account details before posting.
