SHELL=/bin/bash

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

# --------------------------------------------------------------------------------------------------
.PHONY: start
start: ## Start containers and run the app.
	@docker-compose up -d app

# --------------------------------------------------------------------------------------------------
.PHONY: inside
inside: ## Reach OS shell inside app container.
	@docker-compose up -d app
	@docker-compose exec -it app /bin/bash

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
.PHONY: _find_and_delete_pyc
_find_and_delete_pyc: # Remove cache files
	@docker-compose exec app find . -name "*.pyc" -delete

# --------------------------------------------------------------------------------------------------
.PHONY: restart
restart: ## Restart all containers
	@docker-compose restart

.DEFAULT_GOAL := help
