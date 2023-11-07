APP_LOCATION            = "$(PWD)/src"
DOCKER_DIR              = "$(PWD)/docker"
DOCKER_FILE				= "$(PWD)/docker/Dockerfile"

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
.PHONY: _check_running service
_check_running: # Check if a service is running.
# @if [[ "$(docker-compose ps $(service) | grep $(service))" == "" ]]; then echo 'Parado'; else echo "Rodando"; fi
	@command -v "docker-compose ps $(service) | grep $(service) > /dev/null"

# --------------------------------------------------------------------------------------------------
.PHONY: build
build: validate_env ## Build images and run the containers

# Clone the app repository if not yet cloned
#@git clone --branch main git@github.com:stoodibr/stoodi-git.git $(APP_LOCATION)

# Build the custom image we use
	@docker-compose build
# Start the containers
	@docker-compose up -d

# --------------------------------------------------------------------------------------------------
# .PHONY: empty_migration app
# empty_migration: ## Create Django empty migration
# # Use start to ensure the container is running
# 	@docker-compose start postgres
# # Run the command inside the container
# 	@docker-compose exec app python3 manage.py makemigrations --empty $(app)

# --------------------------------------------------------------------------------------------------
.PHONY: up
up: ## Start containers and run the project in dev mode
	@docker-compose up -d app

# --------------------------------------------------------------------------------------------------
.PHONY: run
run: ## Reach command line inside app container
	@docker-compose up -d app
	@docker-compose exec -it app /bin/bash

# --------------------------------------------------------------------------------------------------
.PHONY: down
down: ## Stop containers
	@docker-compose stop

# --------------------------------------------------------------------------------------------------
.PHONY: reset-containers
reset-containers: ## Destroy and recreate all containers from last built images
	@docker-compose down
	@docker-compose up -d

# --------------------------------------------------------------------------------------------------
.PHONY: remove
remove: ## Remove all containers and wipe all data
	@docker-compose down

# --------------------------------------------------------------------------------------------------
# .PHONY: shell-plus shell
# shell-plus: ## Run Django Shell Plus (params:  shell=ipython | shell=bpython | shell=python | shell=plain)
# ifdef shell
# 	@if [[ ${shell} == "python" ]]; then docker-compose exec app python3 manage.py shell_plus --plain --quiet-load; else docker-compose exec app python3 manage.py shell_plus --${shell} --quiet-load; fi
# else
# 	@docker-compose exec app python3 manage.py shell_plus --quiet-load
# endif

# --------------------------------------------------------------------------------------------------
.PHONY: _find_and_delete_pyc
_find_and_delete_pyc: # Remove cache files
	@docker-compose exec app find . -name "*.pyc" -delete

# --------------------------------------------------------------------------------------------------
# .PHONY: test
# test: _find_and_delete_pyc ## Run tests inside stoodi project (params: name=<app> | name=<app.tests.class>)
# 	@docker-compose exec app python3 manage.py test "$(name)"

# --------------------------------------------------------------------------------------------------
.PHONY: restart
restart: ## Restart all containers
	@docker-compose restart

# --------------------------------------------------------------------------------------------------
# .PHONY: env-to-local
# env-to-local: ## Muda o arquivo .env para a configuração para ambiente local
# 	@cp ./deploy/stoodi-git/stoodi_01/.envlocal ./deploy/stoodi-git/stoodi_01/.env
# 	@echo "Arquivo .env modificado para o ambiente local."

.DEFAULT_GOAL := help
