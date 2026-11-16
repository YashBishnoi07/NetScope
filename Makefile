PYTHON ?= python
PIP ?= $(PYTHON) -m pip
BACKEND_DIR := backend
FRONTEND_DIR := frontend

.PHONY: setup backend-install frontend-install test lint format dev-backend dev-frontend docker-up

setup: backend-install frontend-install

backend-install:
	cd $(BACKEND_DIR) && $(PIP) install -r requirements.txt

frontend-install:
	cd $(FRONTEND_DIR) && npm install

test:
	cd $(BACKEND_DIR) && $(PYTHON) -m pytest -q
	cd $(FRONTEND_DIR) && npm test -- --run

lint:
	cd $(BACKEND_DIR) && $(PYTHON) -m ruff check . && $(PYTHON) -m black --check . && $(PYTHON) -m mypy .
	cd $(FRONTEND_DIR) && npx eslint . --ext .ts,.tsx && npx tsc --noEmit

format:
	cd $(BACKEND_DIR) && $(PYTHON) -m black . && $(PYTHON) -m ruff check --fix .
	cd $(FRONTEND_DIR) && npx prettier --write .

dev-backend:
	cd $(BACKEND_DIR) && uvicorn netscope.app:app --host 0.0.0.0 --port 8000 --reload

dev-frontend:
	cd $(FRONTEND_DIR) && npm run dev -- --host 0.0.0.0

docker-up:
	docker compose up --build
