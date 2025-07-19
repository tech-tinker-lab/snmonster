#!/bin/bash

# Docker Installation Script for Rock 5B ARM64 Armbian Ubuntu
# This script installs Docker and Docker Compose and configures non-sudo access

set -e

echo "🐋 Docker Installation Script for Rock 5B ARM64 Armbian Ubuntu"
echo "============================================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running on ARM64
if [[ $(uname -m) != "aarch64" ]]; then
    print_error "This script is designed for ARM64 architecture (aarch64)"
    print_error "Current architecture: $(uname -m)"
    exit 1
fi

print_status "Detected ARM64 architecture: $(uname -m)"

# Check if running on Ubuntu/Debian
if ! command -v apt &> /dev/null; then
    print_error "This script requires apt package manager (Ubuntu/Debian)"
    exit 1
fi

print_status "Detected apt package manager"

# Update package list
print_status "Updating package list..."
sudo apt update

# Install required packages
print_status "Installing required packages..."
sudo apt install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    software-properties-common \
    apt-transport-https

# Remove old Docker installations
print_status "Removing old Docker installations..."
sudo apt remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true

# Add Docker's official GPG key
print_status "Adding Docker's official GPG key..."
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Add Docker repository
print_status "Adding Docker repository..."
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Update package list with Docker repository
print_status "Updating package list with Docker repository..."
sudo apt update

# Install Docker Engine
print_status "Installing Docker Engine..."
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Start and enable Docker service
print_status "Starting and enabling Docker service..."
sudo systemctl start docker
sudo systemctl enable docker

# Get current user
CURRENT_USER=$(whoami)
print_status "Current user: $CURRENT_USER"

# Add user to docker group for non-sudo access
print_status "Adding user '$CURRENT_USER' to docker group..."
sudo usermod -aG docker $CURRENT_USER

# Create docker group if it doesn't exist
sudo groupadd docker 2>/dev/null || true

# Set proper permissions for Docker socket
print_status "Setting proper permissions for Docker socket..."
sudo chown root:docker /var/run/docker.sock
sudo chmod 666 /var/run/docker.sock

# Install Docker Compose standalone (for compatibility)
print_status "Installing Docker Compose standalone..."
DOCKER_COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep -Po '"tag_name": "\K[^"]*')
sudo curl -L "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Create symbolic link for docker-compose
sudo ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose

# Verify installations
print_status "Verifying Docker installation..."
docker --version
docker compose version
docker-compose --version

print_status "Testing Docker with hello-world..."
# Test Docker (will work after group changes take effect)
if docker run hello-world 2>/dev/null; then
    print_status "Docker test successful!"
else
    print_warning "Docker test failed - you may need to log out and log back in"
    print_warning "Or run: newgrp docker"
fi

# Show Docker info
print_status "Docker system information:"
docker info --format "{{.ServerVersion}}" 2>/dev/null || print_warning "Docker info requires group membership to be active"

# Create a simple docker-compose.yml example
print_status "Creating Docker Compose example..."
cat > /tmp/docker-compose-example.yml << 'EOF'
version: '3.8'
services:
  web:
    image: nginx:alpine
    ports:
      - "8080:80"
    volumes:
      - ./html:/usr/share/nginx/html
    restart: unless-stopped

  app:
    image: node:18-alpine
    working_dir: /app
    volumes:
      - ./app:/app
    command: sh -c "npm install && npm start"
    ports:
      - "3000:3000"
    depends_on:
      - web
    restart: unless-stopped
EOF

print_status "Docker Compose example created at /tmp/docker-compose-example.yml"

# Create useful Docker aliases
print_status "Creating useful Docker aliases..."
cat >> ~/.bashrc << 'EOF'

# Docker aliases
alias d='docker'
alias dc='docker compose'
alias dps='docker ps'
alias dpa='docker ps -a'
alias di='docker images'
alias dlog='docker logs'
alias dexec='docker exec -it'
alias dstop='docker stop $(docker ps -q)'
alias dclean='docker system prune -f'
alias dcleanall='docker system prune -af'
EOF

print_status "Docker aliases added to ~/.bashrc"

echo ""
print_status "🎉 Docker installation completed successfully!"
echo ""
print_status "Next steps:"
echo "1. Log out and log back in (or run: newgrp docker)"
echo "2. Test Docker: docker run hello-world"
echo "3. Test Docker Compose: docker compose --version"
echo "4. Check example: cat /tmp/docker-compose-example.yml"
echo ""
print_status "Useful commands:"
echo "  docker ps          - List running containers"
echo "  docker images      - List Docker images"
echo "  docker compose up  - Start services from docker-compose.yml"
echo "  docker system df   - Show Docker disk usage"
echo "  source ~/.bashrc   - Reload aliases"
echo ""
print_warning "Note: You may need to restart your terminal session for group changes to take effect"
print_status "Docker installation script completed! 🐋"
