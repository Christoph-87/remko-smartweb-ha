# Robustness Ideas

Ideas for future improvements around REMKO SmartWeb cloud instability:

- Share one account-level client/cache across multiple config entries using the same credentials, so Home Assistant startup does not trigger parallel logins and device-list requests for every device.
- Keep already configured entities available during short SmartWeb outages when the last known state is available, while still surfacing persistent configuration errors.
- Recommend longer scan intervals, such as 60-120 seconds, when multiple REMKO devices are configured.
