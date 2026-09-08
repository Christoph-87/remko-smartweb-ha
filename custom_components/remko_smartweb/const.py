DOMAIN = "remko_smartweb"

CONF_EMAIL = "email"
CONF_PASSWORD = "password"
CONF_DEVICE_NAME = "device_name"
CONF_DEVICE_PATH = "device_path"
CONF_SCAN_INTERVAL = "scan_interval"
CONF_MIN_TEMP = "min_temp"
CONF_MAX_TEMP = "max_temp"
CONF_MODEL = "model"
CONF_DEVICE_KIND = "device_kind"
CONF_BEEP = "beep"

DEVICE_KIND_AUTO = "auto"
DEVICE_KIND_CLIMATE = "climate"
DEVICE_KIND_DHW = "domestic_hot_water"
DEVICE_KIND_DIAGNOSTICS = "diagnostics"

DEFAULT_SCAN_INTERVAL = 30
DEFAULT_MIN_TEMP = 16
DEFAULT_MAX_TEMP = 30

CONF_LOCAL_MQTT_HOST = "local_mqtt_host"
CONF_LOCAL_MQTT_PORT = "local_mqtt_port"
CONF_LOCAL_MQTT_USER = "local_mqtt_user"
CONF_LOCAL_MQTT_PASSWORD = "local_mqtt_password"
CONF_LOCAL_MQTT_TOPIC = "local_mqtt_topic"

DEFAULT_LOCAL_MQTT_PORT = 1883

PLATFORMS = ["sensor", "climate", "water_heater", "switch", "number", "date"]
