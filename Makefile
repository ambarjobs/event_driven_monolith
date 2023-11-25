SHELL=/bin/bash

include .env

all:
	@echo "Try 'make help'"

# --------------------------------------------------------------------------------------------------
.PHONY: help
help: ## Makefile help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST) | sort

# --------------------------------------------------------------------------------------------------
.PHONY: validate_env
validate_env:
	@command -v docker > /dev/null || (echo "You need to install docker before proceeding" && exit 1)
	@command -v docker-compose > /dev/null || (echo "You need to install docker-compose before proceeding" && exit 1)

# --------------------------------------------------------------------------------------------------
.PHONY: build
build: validate_env ## Build images and run the containers

	@docker-compose stop
# Build the custom image.
	@docker-compose build
# Start the containers
	@docker-compose up -d
# Prompt to wait CouchDB initialization.
	@read -p "Await container [evt-drv-couchdb] to be 'Started' and press <Enter> to initialize database."
# Initialize CouchDB
	@docker-compose exec -d couchdb ./init_couchdb

# --------------------------------------------------------------------------------------------------
.PHONY: start
start: ## Start containers and run the app.
	@docker-compose up -d app

# --------------------------------------------------------------------------------------------------
.PHONY: stop
stop: ## Stop containers.
	@docker-compose stop

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
	@docker-compose restart

.DEFAULT_GOAL := help

# ==================================================================================================
#  General commands
# --------------------------------------------------------------------------------------------------
.PHONY: status
status: ## Show status of the containers.
	@docker-compose ps --format 'table {{.Name}}\t{{.Service}}\t{{.Status}}'

# ==================================================================================================
#  App commands
# --------------------------------------------------------------------------------------------------
.PHONY: inside
inside: ## Reach OS shell inside app container.
	@docker-compose up -d app
	@docker-compose exec -it app /bin/bash

# --------------------------------------------------------------------------------------------------
.PHONY: _find_and_delete_pyc
_find_and_delete_pyc: # Remove Python cache files
	@docker-compose exec app find . -name "*.pyc" -delete

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
