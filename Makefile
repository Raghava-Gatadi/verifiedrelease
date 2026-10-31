.PHONY: setup up down test lab lint logs
setup:
	python3 scripts/setup.py
up: setup
	docker compose up --build -d --wait api
down:
	docker compose down
test: setup
	docker compose --profile test run --build --rm tests
lab: setup
	docker compose --profile test run --build --rm tests sh -c 'DATABASE_URL=$$TEST_OWNER_URL alembic upgrade head && python -m lab.run'
lint: setup
	docker compose --profile test run --build --rm --no-deps tests python -m ruff check app tests lab scripts alembic
logs:
	docker compose logs --tail=80 api keycloak

.PHONY: release-tools release-unit release-demo
release-tools:
	python3 scripts/release/install_tools.py
release-unit:
	python3 -m unittest discover -s release_tests -v
# Requires a built/scanned image and the local loopback registry; see docs/release/demo.md.
release-demo:
	PATH="$(CURDIR)/.tools:$$PATH" python3 scripts/release/demo.py
