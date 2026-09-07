HA_HOST ?= 192.168.2.4
HA_USER ?= christoph
HA_PATH  = /share/docker/home-assistant/custom_components/remko_smartweb
SRC      = custom_components/remko_smartweb

.PHONY: deploy logs test lint

## Deploy to local HA: rsync, fix permissions, restart container.
deploy:
	rsync -avz --delete \
		--exclude '__pycache__' \
		--exclude '*.pyc' \
		$(SRC)/ $(HA_USER)@$(HA_HOST):$(HA_PATH)/
	ssh $(HA_USER)@$(HA_HOST) \
		"sudo chown -R root:root $(HA_PATH) && docker restart homeassistant"

## Tail HA logs filtered to remko + errors.
logs:
	ssh $(HA_USER)@$(HA_HOST) \
		"docker logs -f --tail=80 homeassistant 2>&1 | grep --line-buffered -iE 'remko|smartweb|ERROR|WARNING|Traceback'"

## Run unit tests locally.
test:
	python -m unittest discover -s tests -v

## Quick syntax check on api.py.
lint:
	python -m py_compile $(SRC)/api.py && echo "api.py: OK"
