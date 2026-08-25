.PHONY: help up down logs keygen

# Show available commands
help:
	@echo "========================================="
	@echo "CGI-Protocol Operations Manager"
	@echo "========================================="
	@echo "make up        - Start the production server (Docker)"
	@echo "make down      - Stop the production server"
	@echo "make logs      - View server logs"
	@echo "make keygen ORG=\"Name\" - Generate a new API key instantly"
	@echo "========================================="

up:
	docker-compose up -d

down:
	docker-compose down

logs:
	docker-compose logs -f cgi-gateway

keygen:
	@if [ -z "$(ORG)" ]; then \
		echo "Error: You must provide an organization name."; \
		echo "Usage: make keygen ORG=\"Marketing Department\""; \
		exit 1; \
	fi
	@echo "Generating API Key for $(ORG)..."
	docker-compose exec cgi-gateway python auth/keygen.py --api-key "$(ORG)"
