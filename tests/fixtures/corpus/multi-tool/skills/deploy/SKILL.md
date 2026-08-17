---
name: deploy
description: Deploy the application to staging or production environments.
---

Deploy the service to the specified environment.

1. Run the full test suite
2. Build the Docker image with the current git SHA as tag
3. Push to the container registry
4. Apply the Kubernetes manifests for the target environment

Usage: specify the target environment (staging or production) when invoking.
