# MCPKernel Helm Chart

Deploy MCPKernel — the mandatory MCP/A2A security gateway — on Kubernetes.

## Quick start

```bash
helm install mcpkernel ./deploy/helm/mcpkernel \
  --namespace mcpkernel --create-namespace \
  --set image.tag=0.3.0 \
  --set config.policy.hotReload=true
```

## Production checklist

- Pin `image.tag` to an immutable digest (`@sha256:...`).
- Set `existingSecret` to a pre-created Kubernetes Secret containing
  `health-token` and (optionally) `sigstore-id-token`.
- Provide policy YAML via the `policies:` map, or extend the chart with
  your own ConfigMap and use `extraVolumes` / `extraVolumeMounts`.
- Enable `serviceMonitor.enabled=true` if you run the
  Prometheus-operator stack.
- Enable `networkPolicy.enabled=true` and configure egress to your
  upstream MCP servers only.
- Set `autoscaling.enabled=true` for HPA on CPU.

## Configuration knobs

See [`values.yaml`](mcpkernel/values.yaml) for the full set. The
`config.env` block lets you inject any `MCPKERNEL_*` environment
variable verbatim.

## Verification

```bash
helm lint ./deploy/helm/mcpkernel
helm template mcpkernel ./deploy/helm/mcpkernel | kubectl apply --dry-run=client -f -
```
