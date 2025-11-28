PROJECT_DIR = ./preprocessor/
NODE_MODULES_PATH = $(PROJECT_DIR)node_modules

# Default action
start:
	@if [ ! -d "$(NODE_MODULES_PATH)" ]; then \
		echo "Dependencies not found. Running 'npm install' in $(PROJECT_DIR)..."; \
		cd $(PROJECT_DIR) && npm install && cd ..; \
	fi && \
	echo "Starting the Node.js project..." && \
	cd $(PROJECT_DIR) && npm run start

# The .PHONY declaration ensures that 'start' is always run, even if a file
# named 'start' exists in the directory.
.PHONY: start