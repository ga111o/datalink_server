.PHONY: help build up down logs clean restart status test

help:
	@echo "make build    - Build the Docker image"
	@echo "make up       - Start the server with docker-compose"
	@echo "make down     - Stop the server"
	@echo "make logs     - Show server logs"
	@echo "make restart  - Restart the server"
	@echo "make status   - Show server status"
	@echo "make clean    - Clean up Docker images and volumes"
	@echo "make test     - Test the server (requires server to be running)"
	@echo ""
	@echo "make test     # Test functionality"
	@echo "make logs     # Check logs"

build:
	@echo "Building DataLink Server Docker image..."
	docker-compose build --no-cache

up:
	@echo "Starting DataLink Server..."
	@mkdir -p uploads
	docker-compose down && docker compose build --no-cache && docker-compose up -d
	@echo "Server started! Check status with: make status"

down:
	@echo "Stopping DataLink Server..."
	docker-compose down

logs:
	@echo "Showing DataLink Server logs..."
	docker-compose logs -f datalink-server

restart:
	@echo "Restarting DataLink Server..."
	docker-compose restart
	@echo "Server restarted!"

### local test
status:
	@echo "DataLink Server Status:"
	@echo "======================"
	@docker-compose ps
	@echo ""
	@echo "Health Check:"
	@curl -s http://localhost:22123/health 2>/dev/null | jq . || echo "Server not responding"
	@echo ""
	@echo "Server Status (includes current configuration):"
	@curl -s http://localhost:22123/status 2>/dev/null | jq . || echo "Server not responding"

clean:
	@echo "Cleaning up Docker resources..."
	docker-compose down -v
	docker system prune -f
	@echo "Cleanup completed!"

test:
	@echo "Testing DataLink Server..."
	@echo "Creating test file..."
	@mkdir -p test_data
	@echo "hello world!" > test_data/hello.txt
	@echo "test test" > test_data/test.txt
	@tar -czf test.tar.gz test_data/
	@rm -rf test_data
	@echo ""
	@echo "Testing upload..."
	@RESPONSE=$$(curl -s -X POST http://localhost:22123/upload -F "file=@test.tar.gz"); \
	echo "Upload response: $$RESPONSE"; \
	FILE_ID=$$(echo $$RESPONSE | grep -o '"id":"[0-9]*"' | grep -o '[0-9]*'); \
	if [ -n "$$FILE_ID" ]; then \
		echo "Upload successful! File ID: $$FILE_ID"; \
		echo "Testing download..."; \
		curl -s -X GET http://localhost:22123/download/$$FILE_ID -O -J; \
		if [ -f test.tar.gz ]; then \
			echo "Download successful with original filename!"; \
			echo "File sizes:"; \
			ls -lh test.tar.gz; \
		else \
			echo "Download failed!"; \
		fi; \
	else \
		echo "Upload failed!"; \
	fi
	@rm -f test.tar.gz
	@echo "Test completed!"

dev:
	@echo "Starting server in development mode..."
	@mkdir -p uploads
	go run main.go

build-prod:
	@echo "Building production binary..."
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-s -w" -o datalink_server main.go
	@echo "Binary created: datalink_server" 