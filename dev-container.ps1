# NRF Development Container Management Script for Windows PowerShell
# Usage: .\dev-container.ps1 [build|run|exec|stop|logs]

param(
    [Parameter(Mandatory=$false)]
    [string]$Command
)

$IMAGE_NAME = "nrf-dev"
$CONTAINER_NAME = "nrf-dev-container"
$HOST_PORT = "29510"
$CONTAINER_PORT = "29510"

switch ($Command) {
    "build" {
        Write-Host "Building development image..." -ForegroundColor Green
        docker build -f Dockerfile_dev -t $IMAGE_NAME .
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Development image built successfully!" -ForegroundColor Green
        } else {
            Write-Host "Failed to build development image" -ForegroundColor Red
        }
    }
    
    "run" {
        Write-Host "Starting development container..." -ForegroundColor Green
        
        # Stop existing container if running
        docker stop $CONTAINER_NAME 2>$null
        docker rm $CONTAINER_NAME 2>$null
        
        # Get current directory path for volume mount
        $currentPath = (Get-Location).Path
        
        # Run new container with volume mounts
        docker run -it --name $CONTAINER_NAME `
            -p "${HOST_PORT}:${CONTAINER_PORT}" `
            -v "${currentPath}:/app" `
            --workdir /app `
            $IMAGE_NAME
    }
    
    "exec" {
        Write-Host "Entering development container..." -ForegroundColor Green
        docker exec -it $CONTAINER_NAME bash
    }
    
    "stop" {
        Write-Host "Stopping development container..." -ForegroundColor Yellow
        docker stop $CONTAINER_NAME
    }
    
    "logs" {
        Write-Host "Showing container logs..." -ForegroundColor Cyan
        docker logs -f $CONTAINER_NAME
    }
    
    "restart" {
        Write-Host "Restarting development container..." -ForegroundColor Green
        docker restart $CONTAINER_NAME
        docker exec -it $CONTAINER_NAME bash
    }
    
    default {
        Write-Host "NRF Development Container Management" -ForegroundColor Blue
        Write-Host ""
        Write-Host "Usage: .\dev-container.ps1 [command]" -ForegroundColor White
        Write-Host ""
        Write-Host "Commands:" -ForegroundColor Yellow
        Write-Host "  build    - Build the development Docker image"
        Write-Host "  run      - Start a new development container"
        Write-Host "  exec     - Enter the running development container"
        Write-Host "  stop     - Stop the development container"
        Write-Host "  logs     - Show container logs"
        Write-Host "  restart  - Restart and enter the container"
        Write-Host ""
        Write-Host "Example workflow:" -ForegroundColor Green
        Write-Host "  1. .\dev-container.ps1 build     # Build the development image"
        Write-Host "  2. .\dev-container.ps1 run       # Start and enter the container"
        Write-Host "  3. Inside container: update-code && build-app && run-app"
        Write-Host ""
    }
}
