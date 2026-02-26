# runpod-cli

RunPod CLI — Unofficial auto-generated from OpenAPI spec.

## Features

- REST API commands auto-generated from RunPod's OpenAPI spec
- Serverless job API (run, runsync, status, stream, cancel, retry, purge-queue, health)
- `--dry-run` mode for request inspection
- `--verbose` mode for request/response debugging
- JSON and compact output formats

## Installation

```bash
cargo install runpod-cli
```

## Usage

```bash
# Set your API key
export RUNPOD_API_KEY="your-api-key"

# List pods
runpod-cli pods list

# Submit a serverless job
runpod-cli serverless run <endpoint-id> -i '{"prompt": "hello"}'

# Check job status
runpod-cli serverless status <endpoint-id> <job-id>

# Dry-run (inspect the request without sending)
runpod-cli --dry-run serverless run <endpoint-id> -i '{"prompt": "hello"}'

# Verbose output
runpod-cli -v pods list
```

## Available Commands

```
billing                Manage billing
container-registry-auths  Manage container registry auths
docs                   Manage docs
endpoints              Manage endpoints
network-volumes        Manage network volumes
pods                   Manage pods
templates              Manage templates
serverless             Run serverless jobs (api.runpod.ai/v2)
```

### Serverless Subcommands

```
run          Submit an async job
runsync      Submit a sync job (blocks until complete)
status       Get job status and result
stream       Get streaming output for a job
cancel       Cancel a running or queued job
retry        Retry a failed or timed-out job
purge-queue  Remove all queued jobs from an endpoint
health       Check endpoint health and worker status
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
