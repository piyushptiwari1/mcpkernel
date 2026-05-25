# Grafana Dashboard

`mcpkernel-overview.json` is a ready-to-import Grafana dashboard for the
MCPKernel gateway. It visualizes every Prometheus metric exported by
`mcpkernel.observability.metrics`:

| Panel                                  | Metric                                                     |
|----------------------------------------|------------------------------------------------------------|
| Tool calls / sec by outcome            | `mcpkernel_tool_calls_total`                               |
| Tool-call latency (p50/p95/p99)        | `mcpkernel_tool_call_duration_seconds_bucket`              |
| Policy verdicts                        | `mcpkernel_policy_decisions_total`                         |
| Taint detections                       | `mcpkernel_taint_detections_total`                         |
| Sandbox executions                     | `mcpkernel_sandbox_executions_total`                       |
| Active connections / rate-limit hits   | `mcpkernel_active_connections`, `mcpkernel_rate_limit_hits_total` |
| Audit volume                           | `mcpkernel_audit_entries_total`                            |
| Top denied tools (last 1h)             | `topk(...)` over `mcpkernel_tool_calls_total`              |

## Import

1. Scrape the proxy's `/metrics` endpoint from Prometheus.
   `deploy/prometheus.yml` already has a `mcpkernel` job — point it at
   your host.
2. In Grafana → **Dashboards → New → Import**, upload
   `mcpkernel-overview.json` (or paste its contents).
3. Select your Prometheus datasource for the `DS_PROMETHEUS` variable.

## Provisioning (Kubernetes / Docker Compose)

Mount the JSON into Grafana's provisioning path:

```yaml
# docker-compose.yml fragment
services:
  grafana:
    image: grafana/grafana:latest
    volumes:
      - ./deploy/grafana/mcpkernel-overview.json:/var/lib/grafana/dashboards/mcpkernel-overview.json:ro
      - ./deploy/grafana/provisioning:/etc/grafana/provisioning:ro
```

With a `provisioning/dashboards/mcpkernel.yaml`:

```yaml
apiVersion: 1
providers:
  - name: 'mcpkernel'
    folder: 'MCPKernel'
    type: file
    options:
      path: /var/lib/grafana/dashboards
```
