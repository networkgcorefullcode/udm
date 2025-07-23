#!/bin/bash

# Development container management script for NRF application
# Usage: ./dev-container.sh [build|run|exec|stop|logs]

IMAGE_NAME="nrf-dev"
CONTAINER_NAME="nrf-dev-container"
HOST_PORT="8003"
CONTAINER_PORT="8000"

case "$1" in
    "build")
        echo "Building development image..."
        docker build -f Dockerfile_dev -t $IMAGE_NAME .
        echo "Development image built successfully!"
        ;;
    
    "run")
        echo "Starting development container..."
        # Stop existing container if running
        docker stop $CONTAINER_NAME 2>/dev/null || true
        docker rm $CONTAINER_NAME 2>/dev/null || true
        
        # Run new container with volume mounts and persistent Go packages
        docker network create --subnet=172.28.0.0/16 net5g
        docker volume create nrf-go-pkg-cache 2>/dev/null || true
        docker run -it --name $CONTAINER_NAME \
            --network net5g --ip 172.28.0.2 \
            -p $HOST_PORT:$CONTAINER_PORT \
            -v "$(pwd):/app" \
            -v nrf-go-pkg-cache:/go/pkg/mod \
            --workdir /app \
            $IMAGE_NAME
        ;;
    
    "exec")
        echo "Entering development container..."
        docker exec -it $CONTAINER_NAME bash
        ;;
    
    "stop")
        echo "Stopping development container..."
        docker stop $CONTAINER_NAME
        ;;
    
    "logs")
        echo "Showing container logs..."
        docker logs -f $CONTAINER_NAME
        ;;
    
    "restart")
        echo "Restarting development container..."
        docker restart $CONTAINER_NAME
        docker exec -it $CONTAINER_NAME bash
        ;;
    
    *)
        echo "NRF Development Container Management"
        echo ""
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  build    - Build the development Docker image"
        echo "  run      - Start a new development container"
        echo "  exec     - Enter the running development container"
        echo "  stop     - Stop the development container"
        echo "  logs     - Show container logs"
        echo "  restart  - Restart and enter the container"
        echo ""
        echo "Example workflow:"
        echo "  1. $0 build     # Build the development image"
        echo "  2. $0 run       # Start and enter the container"
        echo "  3. Inside container: update-code && build-app && run-app"
        echo ""
        ;;
esac
