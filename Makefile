SHELL=/bin/bash

include .env

COUCHDB_SETUP_DELAY = 10

all:
	@echo "Try 'make help'"

# --------------------------------------------------------------------------------------------------
.PHONY: help
help: ## Makefile help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST) | sort

# --------------------------------------------------------------------------------------------------
.PHONY: validate_env
validate_env: ## Validate docker environment requirements.
	@command -v docker > /dev/null || (echo "You need to install docker before proceeding" && exit 1)
	@command -v docker-compose > /dev/null || (echo "You need to install docker-compose before proceeding" && exit 1)

# --------------------------------------------------------------------------------------------------
.PHONY: build
build: validate_env ## Build images and start the containers.

	@docker-compose stop
# Build the custom image.
	@docker-compose build
# Start couchdb container
	@docker-compose up -d couchdb
# Prompt to wait CouchDB initialization.
#	@read -p "Wait some seconds after container [evt-drv-couchdb] to be 'Started' and press <Enter> to initialize database."
	@echo "Waiting for CouchDB to set up ..."
	@sleep $(COUCHDB_SETUP_DELAY)
# Initialize CouchDB
	@docker-compose exec -d couchdb ./init_couchdb
# Start remaining containers
	@docker-compose up -d

# --------------------------------------------------------------------------------------------------
.PHONY: start
start: ## Start containers.
	@docker-compose up -d

# --------------------------------------------------------------------------------------------------
.PHONY: stop
stop: ## Stop containers.
	@docker-compose stop

# --------------------------------------------------------------------------------------------------
.PHONY: reset-build
reset-build: ## Remove build's containers and images.
	@docker-compose stop
	@docker rm -v evt-drv-app evt-drv-couchdb evt-drv-rabbitmq
	@docker rmi event_driven_normal_scale_app-app event_driven_normal_scale_app-couchdb

# --------------------------------------------------------------------------------------------------
.PHONY: reset-containers
reset-containers: ## Destroy and recreate all containers from last built images.
	@docker-compose down
	@docker-compose up -d

# --------------------------------------------------------------------------------------------------
.PHONY: remove-all
remove: ## Remove all containers and wipe all data
	@docker-compose down

# --------------------------------------------------------------------------------------------------
.PHONY: restart
restart: ## Restart all containers
	@docker-compose stop
	@sleep 3
	@docker-compose up -d

.DEFAULT_GOAL := help

# ==================================================================================================
#  General commands
# --------------------------------------------------------------------------------------------------
.PHONY: status
status: ## Show status of the containers.
	@docker-compose ps --format 'table {{.Name}}\t{{.Service}}\t{{.Status}}'

# --------------------------------------------------------------------------------------------------
.PHONY: logs service
logs: ## Show status of the containers.
	@docker-compose logs -t -f ${service}

# ==================================================================================================
#  App commands
# --------------------------------------------------------------------------------------------------
.PHONY: app_status
app_status: ## Show status of the app container.
	@docker inspect evt-drv-app --format "{{.State.Status}}"

# --------------------------------------------------------------------------------------------------
.PHONY: inside
inside: ## Reach OS shell inside app container.
	@docker-compose exec -it app /bin/bash

# --------------------------------------------------------------------------------------------------
.PHONY: shell
shell: ## Python shell inside app container.
	@docker-compose exec -it app /usr/local/bin/bpython

# --------------------------------------------------------------------------------------------------
.PHONY: prep-dev
prep-dev: ## Prepare inside environment for development.
	@docker-compose exec -it app /deploy/prep_dev

# --------------------------------------------------------------------------------------------------
.PHONY: delete_bytecode
delete_bytecode: # Remove Python bytecode compiled files
	@docker-compose exec app find . -name "*.pyc" -delete
	@docker-compose exec app find . -name "__pycache__" -delete

# --------------------------------------------------------------------------------------------------
.PHONY: test file class test_name module
test: # Execute test suite, optionally restricted to a `file`, `class`, `test_name` or `module`.
ifdef module
	@docker-compose exec app pytest -k ${module}
else ifdef test_name
	@docker-compose exec app pytest tests/${file}::${class}::${test_name}
else ifdef class
	@docker-compose exec app pytest tests/${file}::${class}
else ifdef file
	@docker-compose exec app pytest tests/${file}
else
	@docker-compose exec app pytest
endif

# ==================================================================================================
#  CouchDB commands
# --------------------------------------------------------------------------------------------------
.PHONY: inside-db
inside-db: ## Reach OS shell inside CouchDB container.
	@docker-compose exec -it couchdb /bin/bash

# --------------------------------------------------------------------------------------------------
.PHONY: init-db
init-db: ## Initialize CouchDB and create app user.
	@docker-compose exec -d couchdb ./init_couchdb

# ==================================================================================================
#  Rabbitmq commands
# --------------------------------------------------------------------------------------------------
.PHONY: inside-rabbit
inside-rabbit: ## Reach OS shell inside RabitMQ container.
	@docker-compose exec -it rabbitmq /bin/bash
