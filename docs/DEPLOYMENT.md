# Deployment Guide

This guide covers production deployment of nonce-cracker for enterprise environments.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Docker Deployment](#docker-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Configuration](#configuration)
- [Monitoring](#monitoring)
- [Security](#security)
- [Troubleshooting](#troubleshooting)

## Overview

nonce-cracker is a CPU-intensive application designed for high-performance ECDSA key recovery. In production, it should be deployed with:

- Resource limits to prevent cluster disruption
- Persistent storage for logs
- Health checks and monitoring
- Graceful shutdown handling

## Prerequisites

### System Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU Cores | 4 | 16+ |
| RAM | 4 GB | 16+ GB |
| Disk | 10 GB | 100+ GB (for large search ranges) |
| Network | None required | N/A |

For BSGS searches (ranges > 2^32 candidates), memory scales with `O(sqrt(N))` up to a maximum of ~5 GB at the BSGS memory guard (`BSGS_MAX_M = 2^26`).

### Software Requirements

- Docker 24.0+ or containerd
- Kubernetes 1.27+ (for K8s deployment)
- kubectl configured with cluster access

## Docker Deployment

### Quick Start

```bash
# Build the image
docker build -t nonce-cracker:latest .

# Run the example
docker run --rm nonce-cracker:latest example

# Run with custom parameters
docker run --rm \
  -e NONCE_CRACKER_LOG_LEVEL=debug \
  -e NONCE_CRACKER_MAX_THREADS=8 \
  -v $(pwd)/logs:/app/logs \
  nonce-cracker:latest run \
  --r1 0x... --r2 0x... --s1 0x... --s2 0x... \
  --z1 0x... --z2 0x... --pubkey 0x...
```

### Production Dockerfile

The multi-stage Dockerfile provides three targets:

- `production`: Minimal runtime image (~50MB)
- `development`: Includes debugging tools
- `builder`: Contains build dependencies

```bash
# Build production image
docker build --target production -t nonce-cracker:prod .

# Build development image
docker build --target development -t nonce-cracker:dev .
```

## Kubernetes Deployment

### Namespace and RBAC

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: nonce-cracker
  labels:
    app.kubernetes.io/name: nonce-cracker
    app.kubernetes.io/component: crypto-tool
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: nonce-cracker
  namespace: nonce-cracker
```

### ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: nonce-cracker-config
  namespace: nonce-cracker
data:
  NONCE_CRACKER_LOG_LEVEL: "info"
  NONCE_CRACKER_MAX_THREADS: "16"
  NONCE_CRACKER_LOG_CONSOLE: "false"
```

### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nonce-cracker
  namespace: nonce-cracker
  labels:
    app.kubernetes.io/name: nonce-cracker
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: nonce-cracker
  template:
    metadata:
      labels:
        app.kubernetes.io/name: nonce-cracker
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"
    spec:
      serviceAccountName: nonce-cracker
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: nonce-cracker
        image: nonce-cracker:latest
        imagePullPolicy: IfNotPresent
        envFrom:
        - configMapRef:
            name: nonce-cracker-config
        resources:
          requests:
            memory: "4Gi"
            cpu: "4"
          limits:
            memory: "32Gi"
            cpu: "16"
        volumeMounts:
        - name: logs
          mountPath: /app/logs
        livenessProbe:
          exec:
            command:
            - /app/nonce-cracker
            - --help
          initialDelaySeconds: 5
          periodSeconds: 30
        readinessProbe:
          exec:
            command:
            - /app/nonce-cracker
            - --help
          initialDelaySeconds: 5
          periodSeconds: 10
      volumes:
      - name: logs
        emptyDir: {}
      terminationGracePeriodSeconds: 60
```

### Job for One-Off Searches

For batch key recovery operations, use a Kubernetes Job:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: key-recovery-search
  namespace: nonce-cracker
spec:
  ttlSecondsAfterFinished: 86400
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      containers:
      - name: nonce-cracker
        image: nonce-cracker:latest
        command:
        - /app/nonce-cracker
        - run
        - --r1
        - "$(R1)"
        - --r2
        - "$(R2)"
        - --s1
        - "$(S1)"
        - --s2
        - "$(S2)"
        - --z1
        - "$(Z1)"
        - --z2
        - "$(Z2)"
        - --pubkey
        - "$(PUBKEY)"
        - --start
        - "$(START)"
        - --end
        - "$(END)"
        env:
        - name: R1
          valueFrom:
            secretKeyRef:
              name: signature-data
              key: r1
        # ... other signature values
        - name: NONCE_CRACKER_LOG_LEVEL
          value: "info"
        - name: NONCE_CRACKER_MAX_THREADS
          value: "32"
        resources:
          requests:
            memory: "8Gi"
            cpu: "8"
          limits:
            memory: "32Gi"
            cpu: "32"
        volumeMounts:
        - name: results
          mountPath: /app/logs
      volumes:
      - name: results
        persistentVolumeClaim:
          claimName: key-recovery-results
```

## Configuration

### Environment Variables

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `NONCE_CRACKER_LOG_DIR` | Log output directory | `logs` | `/var/log/nonce-cracker` |
| `NONCE_CRACKER_LOG_LEVEL` | Log verbosity | `info` | `debug` |
| `NONCE_CRACKER_LOG_CONSOLE` | Enable console output | `true` | `false` |
| `NONCE_CRACKER_MAX_THREADS` | Max worker threads | `256` | `16` |

### Secret Management

For production deployments, signature data should be stored as Kubernetes Secrets:

```bash
kubectl create secret generic signature-data \
  --from-literal=r1=0x... \
  --from-literal=s1=0x... \
  --from-literal=z1=0x... \
  --namespace=nonce-cracker
```

## Monitoring

### Metrics

The application emits structured metrics logs:

```
2026-04-23T01:44:00.123456Z INFO nonce-cracker::metrics: event="search_complete" found=true delta=1 elapsed_sec=0.123 threads=8
```

### Health Checks

- **Liveness**: Verifies process is responsive
- **Readiness**: Verifies configuration is valid

### Alerts

Recommended alerting rules:

```yaml
- alert: NonceCrackerHighErrorRate
  expr: |
    rate(nonce_cracker_errors_total[5m]) > 0.1
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "High error rate in nonce-cracker"

- alert: NonceCrackerSearchStalled
  expr: |
    rate(nonce_cracker_candidates_evaluated_total[5m]) == 0
  for: 10m
  labels:
    severity: critical
  annotations:
    summary: "Search appears to be stalled"
```

## Security

### Container Security

The production image:
- Runs as non-root user (UID 1000)
- Has minimal attack surface (no shell, no package manager)
- Uses distroless base image

### Network Security

- No network listeners required
- No inbound connections needed
- Can run in air-gapped environments

### Secret Handling

```yaml
# Bad: Hardcoded in ConfigMap
apiVersion: v1
kind: ConfigMap
data:
  r1: "0xdeadbeef..."  # DON'T DO THIS

# Good: Reference to Secret
apiVersion: v1
kind: ConfigMap
data:
  r1: "$(R1)"  # Reference from env
```

## Troubleshooting

### High Memory Usage

If the application is consuming too much memory:

1. Check if BSGS is active (ranges > 2^32 use more memory). Reduce search range to force parallel scan.
2. Check thread count: `NONCE_CRACKER_MAX_THREADS`
3. Monitor with `kubectl top pod`
4. Set memory limits in resources

### Slow Performance

1. Verify CPU allocation matches thread count
2. Check for CPU throttling: `kubectl describe pod`
3. Enable debug logging for detailed timing

### Logs Not Appearing

1. Check `NONCE_CRACKER_LOG_DIR` permissions
2. Verify volume mounts are correct
3. Check `NONCE_CRACKER_LOG_CONSOLE` setting

### Graceful Shutdown Issues

If shutdown is not graceful:

1. Check `terminationGracePeriodSeconds`
2. Verify signal handlers are registered
3. Monitor for `SIGTERM` receipt in logs

## Best Practices

1. **Resource Planning**: Calculate required CPU/RAM based on search range. BSGS ranges need more memory.
2. **Storage**: Use persistent volumes for long-running searches
3. **Secrets**: Never commit secrets to version control
4. **Monitoring**: Set up alerts for completion and errors
5. **Testing**: Validate configuration in staging before production

## Support

For issues or questions:
- Check logs: `kubectl logs -n nonce-cracker deployment/nonce-cracker`
- Review metrics: Look for `nonce-cracker::metrics` target
- Enable debug: Set `NONCE_CRACKER_LOG_LEVEL=debug`
