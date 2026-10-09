# Configuration Reference

Configuration is stored at `~/.spectre/config.yaml`.

## Managing via CLI

```bash
spectre config set ai_enabled true
spectre config set ai_provider openai
spectre config get ai_provider
```

## Config File

```yaml
scan:
  threads: 50        # Max concurrent requests
  timeout: 30        # Per-scanner timeout (seconds)
  retries: 3         # Retry count on failure
  proxy: ""          # HTTP proxy URL (e.g. http://127.0.0.1:8080)
  rate_limit: 0      # Requests per second (0 = unlimited)
  user_agent: "Spectre/0.1.0"

ai:
  enabled: false
  provider: "openai" # openai | anthropic
  model: "gpt-4"

scanners:
  web:
    enabled: true
  subdomain:
    enabled: true
  secrets:
    enabled: true
  port:
    enabled: true
  tech:
    enabled: true
  ssl:
    enabled: true

reporting:
  output_dir: "./reports"

integrations:
  slack:
    enabled: false
    webhook_url: ""
  discord:
    enabled: false
    webhook_url: ""
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | OpenAI API key for AI features |
| `ANTHROPIC_API_KEY` | Anthropic API key for AI features |
| `SPECTRE_CONFIG` | Override config file path |
