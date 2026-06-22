# Confidential Agents API

The Confidential Agents API provisions and manages per-organization confidential VM (CVM) instances that run packaged agents such as OpenClaw. Each instance is a hardware-isolated workload running inside a Trusted Execution Environment, addressable over SSH and uniquely named under your organization subdomain.

## Quickstart

This walkthrough creates an instance, waits until it is ready, reads its instance record, and deletes it. The examples use [curl](https://curl.se/) and [jq](https://jqlang.org/).

#### 1. Obtain credentials

Organizations and API keys are provisioned by Confidential. To request access, [contact us](mailto:hello@confidential.ai).

When your organization is created, you receive:

- An organization slug, used in instance hostnames such as `{instance-name}.{organization-slug}.confidential.ai`.
- An API key, used as a Bearer token for API requests.

Export both values before running the examples:

```bash
export API_BASE="https://api.confidential.ai"
export ORGANIZATION_SLUG="acme"
export CA_API_KEY="confai_live_replace_with_your_key"
```

#### 2. Test your API key

Call the usage endpoint. A successful response returns a `data.pricing` object and a `data.usage` object for the current billing cycle.

```bash
curl -sS "$API_BASE/v1/usage" \
  -H "Authorization: Bearer $CA_API_KEY" \
  | jq .
```

#### 3. Create an instance

Use any valid OpenSSH public key (`ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-*`, etc.). We recommend `ssh-ed25519` for new keys; `ssh-rsa` is supported for backwards compatibility but should be at least 2048 bits.

```bash
export SSH_PUBLIC_KEY="$(cat ~/.ssh/id_ed25519.pub)"

CREATE_RESPONSE="$(
  curl -sS -X POST "$API_BASE/v1/instances" \
    -H "Authorization: Bearer $CA_API_KEY" \
    -H "Content-Type: application/json" \
    --data "$(jq -n --arg public_key "$SSH_PUBLIC_KEY" '{
      public_key: $public_key,
      agent: "openclaw",
      inference_mode: "default_gateway"
    }')"
)"

echo "$CREATE_RESPONSE" | jq .

export INSTANCE_NAME="$(echo "$CREATE_RESPONSE" | jq -r '.data.name')"
export INSTANCE_HOSTNAME="$(echo "$CREATE_RESPONSE" | jq -r '.data.hostname')"
```

The create response is `202 Accepted`. The instance starts in `provisioning`.

#### 4. Get instance info

```bash
curl -sS "$API_BASE/v1/instances/$INSTANCE_NAME" \
  -H "Authorization: Bearer $CA_API_KEY" \
  | jq .
```

The response includes fields such as `name`, `status`, `agent`, `hostname`, `inference_mode`, `created_at`, and `ready_at`.

#### 5. Poll until the instance is ready

There are no webhooks for instance state changes. Poll `GET /v1/instances/{name}` until `status` becomes `ready`.

```bash
while true; do
  INSTANCE_RESPONSE="$(
    curl -sS "$API_BASE/v1/instances/$INSTANCE_NAME" \
      -H "Authorization: Bearer $CA_API_KEY"
  )"

  STATUS="$(echo "$INSTANCE_RESPONSE" | jq -r '.data.status')"
  echo "status=$STATUS"

  if [ "$STATUS" = "ready" ]; then
    export INSTANCE_HOSTNAME="$(echo "$INSTANCE_RESPONSE" | jq -r '.data.hostname')"
    break
  fi

  if [ "$STATUS" = "failed" ]; then
    echo "$INSTANCE_RESPONSE" | jq .
    exit 1
  fi

  sleep 15
done

echo "Instance is ready: $INSTANCE_HOSTNAME"
```

Once the instance is ready, connect over SSH with the private key that matches the public key from the create request:

```bash
ssh -i ~/.ssh/id_ed25519 "$INSTANCE_HOSTNAME"
```

#### 6. Verify the CVM attestation

`ccvm` is a CLI that runs inside the CVM and validates the hardware attestation, TPM measurements, host-key fingerprints, and inference gateway attestation chain — confirming the CVM is what it claims to be and is connected to the expected gateway. Run it from within the SSH session immediately after claiming the instance.

```bash
ccvm verify
```

Example output:

```
[1/5] SEV-SNP Hardware              PASS
[2/5] TPM Attestation               PASS
[3/5] Host Key Binding              PASS
[4/5] Inference Provider            PASS
[5/5] External Access Lockout       PASS  (FAIL on staging — debug SSH access intentional)
```

The tool is open source: [github.com/confidential-dot-ai/confidential-cvm-cli](https://github.com/confidential-dot-ai/confidential-cvm-cli).

#### 7. Delete the instance

When you are done, delete the instance. The response is 202 Accepted with status: `terminating`. The instance reaches `terminated` asynchronously once Azure resources are cleaned up.

```bash
curl -sS -X DELETE "$API_BASE/v1/instances/$INSTANCE_NAME" \
  -H "Authorization: Bearer $CA_API_KEY" \
  | jq .
```

## Endpoints

All endpoints are served from `https://api.confidential.ai` and versioned under `/v1`.

### Create Instance

```http
POST /v1/instances
```

Provisions a new confidential VM under your organization. Returns `202 Accepted` with the generated instance `name`. Provisioning typically completes within a few minutes; poll the Retrieve Instance endpoint until `status` flips from `provisioning` to `ready`.

#### Headers

| Header | Required | Description |
| --- | --- | --- |
| `Authorization` | yes | `Bearer <api-key>`. |
| `Idempotency-Key` | recommended | Prevents duplicate provisioning on retry. See below. |
| `X-Correlation-ID` | optional | Client-supplied tag echoed back on the response. |

#### Idempotency-Key

`Idempotency-Key` prevents duplicate side effects when retrying `POST /v1/instances`. It is **not** a request ID and **not** a correlation ID — each retry still receives a fresh `request_id`.

- A duplicate request within 24 hours returns the original result and does **not** provision a second CVM.
- The response body is the original API result, but `request_id` and `correlation_id` reflect the current attempt.
- Reusing the same `Idempotency-Key` with a different request body returns `409 conflict`.

#### Request body

```json
{
  "public_key": "ssh-ed25519 AAAAC3... user@example",
  "agent": "openclaw",
  "inference_mode": "default_gateway",
  "inference_model": "<model-id>"
}
```

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `public_key` | string | yes | OpenSSH-formatted public key (`ssh-rsa`, `ssh-ed25519`, `ecdsa-sha2-*`, etc.). We recommend `ssh-ed25519` for new keys; `ssh-rsa` is accepted for backwards compatibility. |
| `agent` | string | no | Packaged agent to install. Defaults to `openclaw`. Currently `openclaw` is the only supported value. |
| `inference_mode` | string | no | Inference routing mode. If omitted, the platform selects one for you. Currently `default_gateway` is the only supported value. |
| `inference_model` | string | no | Model identifier to use through the default inference gateway. **If omitted, the platform selects a model for you and returns the chosen identifier in every subsequent response for this instance.** Specify this field only if you need a particular model. |

#### Response — `202 Accepted`

```json
{
  "request_id": "4f1f6b6ab27d49bdb1a6a7a21c9f3b42",
  "correlation_id": null,
  "data": {
    "name": "4k9p2xq7",
    "status": "provisioning",
    "agent": "openclaw",
    "hostname": "4k9p2xq7.acme.confidential.ai",
    "public_key": "ssh-ed25519 AAAAC3... user@example",
    "inference_mode": "default_gateway",
    "inference_model": "<model-id>",
    "egress_limit_bytes": 5368709120,
    "created_at": "2026-05-01T20:14:22Z"
  }
}
```

Once `status` reaches `ready`, connect over SSH:

```bash
ssh <hostname>
```

If your SSH client requires an explicit user or key path:

```bash
ssh -i <private-key-path> <hostname>
```

#### Errors

| Code | HTTP | When |
| --- | --- | --- |
| `invalid_request` | `400` | `public_key` is missing or not a valid OpenSSH public key, or an unsupported `agent` or `inference_mode` was supplied. |
| `unauthenticated` | `401` | Missing or invalid Bearer token. |
| `conflict` | `409` | The same `Idempotency-Key` was reused with a different request body. |

### List Instances

```http
GET /v1/instances
```

Returns all instances belonging to your organization, including terminated instances retained for the 30-day name-reservation window.

#### Response — `200 OK`

```json
{
  "request_id": "4f1f6b6ab27d49bdb1a6a7a21c9f3b42",
  "correlation_id": null,
  "data": {
    "instances": [
      {
        "name": "4k9p2xq7",
        "status": "ready",
        "agent": "openclaw",
        "hostname": "4k9p2xq7.acme.confidential.ai",
        "public_key": "ssh-ed25519 AAAAC3... user@example",
        "inference_mode": "default_gateway",
        "inference_model": "<model-id>",
        "egress_limit_bytes": 5368709120,
        "failure_code": null,
        "failure_message": null,
        "terminated_reason": null,
        "created_at": "2026-05-01T20:14:22Z",
        "ready_at": "2026-05-01T20:18:33Z",
        "terminated_at": null
      }
    ],
    "next_cursor": null
  }
}
```

See the Status enum under Retrieve Instance below for the full list of `status` values and field semantics.

#### Pagination

The response includes `next_cursor`, currently always `null`. Cursor pagination will be activated in a future release; the response shape is stable.

### Retrieve Instance

```http
GET /v1/instances/{name}
```

Returns the full record for one instance. Use this endpoint to poll provisioning status and to read current state.

There are no webhooks for instance state changes — poll this endpoint instead.

#### Path parameters

| Parameter | Description |
| --- | --- |
| `name` | The 8-character generated instance name, e.g. `4k9p2xq7`. |

#### Response — `200 OK`

```json
{
  "request_id": "4f1f6b6ab27d49bdb1a6a7a21c9f3b42",
  "correlation_id": "venice-job-2026-05-03-001",
  "data": {
    "name": "4k9p2xq7",
    "status": "ready",
    "agent": "openclaw",
    "hostname": "4k9p2xq7.acme.confidential.ai",
    "public_key": "ssh-ed25519 AAAAC3... user@example",
    "inference_mode": "default_gateway",
    "inference_model": "<model-id>",
    "egress_limit_bytes": 5368709120,
    "failure_code": null,
    "failure_message": null,
    "terminated_reason": null,
    "created_at": "2026-05-01T20:14:22Z",
    "ready_at": "2026-05-01T20:18:33Z",
    "terminated_at": null
  }
}
```

#### Status enum

| Value | Meaning |
| --- | --- |
| `provisioning` | Instance is being claimed or cold-started. |
| `ready` | SSH is reachable and claim-time setup has completed. Run in-CVM verification to confirm attestation before trusting the workload. |
| `failed` | Provisioning failed terminally. `failure_code` and `failure_message` may be populated. |
| `terminating` | `DELETE /v1/instances/{name}` has been accepted and resource teardown is in progress. The instance transitions to `terminated` once Azure resources are fully released. |
| `terminated` | Resources have been released. The record and name reservation are retained for at least 30 days. |

#### Egress

Each instance has a hard 5 GB egress limit per its lifetime. The platform monitors per-VM network egress and enforces the limit at the instance firewall layer once the threshold is observed. `egress_limit_bytes` is reported on every instance record.

#### Errors

| Code | HTTP | When |
| --- | --- | --- |
| `not_found` | `404` | Instance does not exist or belongs to another organization. |
| `unauthenticated` | `401` | Missing or invalid Bearer token. |

### Delete Instance

```http
DELETE /v1/instances/{name}
```

Tears down the CVM and removes its DNS record. The database row is retained with a terminal status, and the name remains reserved for at least 30 days.

Returns `202 Accepted` with status: `terminating`. Azure resource teardown completes asynchronously; the instance transitions to `terminated` once cleanup finishes. Poll `GET /v1/instances/{name}` until status is `terminated` if you need confirmation that resources have been released.

#### Path parameters

| Parameter | Description |
| --- | --- |
| `name` | The 8-character generated instance name, e.g. `4k9p2xq7`. |

#### Response — `202 Accepted`

```json
{
  "request_id": "4f1f6b6ab27d49bdb1a6a7a21c9f3b42",
  "correlation_id": null,
  "data": {
    "name": "4k9p2xq7",
    "status": "terminating",
    "agent": "openclaw",
    "hostname": "4k9p2xq7.acme.confidential.ai",
    "public_key": "ssh-ed25519 AAAAC3... user@example",
    "inference_mode": "default_gateway",
    "inference_model": "<model-id>",
    "egress_limit_bytes": 5368709120,
    "failure_code": null,
    "failure_message": null,
    "terminated_reason": "deleted_via_api",
    "created_at": "2026-05-01T20:14:22Z",
    "ready_at": "2026-05-01T20:18:33Z",
    "terminated_at": null
  }
}
```

#### Errors

| Code | HTTP | When |
| --- | --- | --- |
| `not_found` | `404` | Instance does not exist or belongs to another organization. |
| `unauthenticated` | `401` | Missing or invalid Bearer token. |

### Get Usage

```http
GET /v1/usage
```

Returns the current billing-cycle consumption summary for your organization — the same numbers that drive your invoice.

#### Response — `200 OK`

```json
{
  "request_id": "4f1f6b6ab27d49bdb1a6a7a21c9f3b42",
  "correlation_id": null,
  "data": {
    "pricing": {
      "period_start": "2026-04-15T14:32:11Z",
      "period_end": "2026-05-15T14:32:11Z",
      "subscription_cost_usd": "200.00",
      "instance_hours_included": 200,
      "overage_per_hour_usd": "0.45"
    },
    "usage": {
      "instance_hours_used": 142.7,
      "inference_cost_usd": "28.23",
      "egress_bytes": 1048576,
      "egress_limit_bytes": 5368709120,
      "egress_observed_at": "2026-05-01T20:14:22Z",
      "egress_blocked": false,
      "egress_block_applied_at": null
    }
  }
}
```

#### `pricing` fields

| Field | Description |
| --- | --- |
| `period_start`, `period_end` | Start and end of the current billing window (ISO 8601). The window is anchored to your organization's signup time, not to calendar months. |
| `subscription_cost_usd` | Base subscription cost for the period. |
| `instance_hours_included` | Instance-hours included in the base subscription. |
| `overage_per_hour_usd` | Cost per instance-hour beyond the included amount. |

#### `usage` fields

| Field | Description |
| --- | --- |
| `instance_hours_used` | Total instance-hours consumed this period across all instances. |
| `inference_cost_usd` | Inference spend this period through the default gateway. |
| `egress_bytes` | Most recent observed egress total for the active instance(s). |
| `egress_limit_bytes` | Per-instance hard egress limit. |
| `egress_observed_at` | When the egress total was last sampled. |
| `egress_blocked` | `true` if egress is currently blocked at the firewall. |
| `egress_block_applied_at` | When the block was applied, or `null`. |

Per-day and per-instance usage breakdowns are not currently exposed through the API.

## Authentication

All endpoints require a Bearer token in the `Authorization` header:

```http
Authorization: Bearer ca_<8 char lowercase alphanumeric>_<18 char lowercase alphanumeric>
```

#### Obtaining credentials

Organizations and API keys are provisioned by Confidential. To request access, [contact us](mailto:hello@confidential.ai). Self-service signup through the public API is not currently available.

When your organization is created, you receive:

- An **organization slug** (e.g. `acme`), which is used in your per-organization subdomain (`{instance-name}.acme.confidential.ai`).
- One or more **API keys** of the form `ca_<prefix>_<secret>`, where `prefix` and `secret` are lowercase alphanumeric strings (8 and 18 characters respectively). Treat these as secrets — anyone with the key can provision and delete instances against your organization.

#### Authentication errors

A missing, malformed, or unknown token returns:

```json
{
  "request_id": "4f1f6b6ab27d49bdb1a6a7a21c9f3b42",
  "correlation_id": null,
  "error": {
    "code": "unauthenticated",
    "message": "missing or invalid Bearer token"
  }
}
```

A valid token used against an organization or resource it is not authorized for returns `forbidden` (`403`). See the error code table under Conventions below.

## Conventions

#### Response envelope

Every JSON response is wrapped in a consistent envelope. On success:

```json
{
  "request_id": "4f1f6b6ab27d49bdb1a6a7a21c9f3b42",
  "correlation_id": "venice-job-2026-05-03-001",
  "data": { }
}
```

On error:

```json
{
  "request_id": "4f1f6b6ab27d49bdb1a6a7a21c9f3b42",
  "correlation_id": null,
  "error": {
    "code": "invalid_request",
    "message": "public_key is not a valid OpenSSH public key: ...",
    "param": "public_key"
  }
}
```

- `request_id` — server-generated identifier for this HTTP request. Always present. Quote it when contacting support.
- `correlation_id` — the value of the `X-Correlation-ID` request header if you sent one, otherwise `null`.
- `error.param` — present when the error maps cleanly to a single request field.
- `error.message` — safe to surface to end users.

The same `request_id` is mirrored in the `X-Request-ID` response header. If you supplied an `X-Correlation-ID`, it is echoed back in `X-Correlation-ID` on the response.

#### Request IDs and Correlation IDs

The API generates the canonical `request_id` for every request. Clients cannot choose it. If you send `X-Request-ID`, it is ignored and a fresh server-side ID is generated.

To tag requests for your own tracking, send `X-Correlation-ID`:

```http
X-Correlation-ID: venice-job-2026-05-03-001
```

Correlation IDs are not required to be unique and the server does not enforce a format.

#### Error codes

| Code | HTTP | Meaning |
| --- | --- | --- |
| `invalid_request` | `400` | Malformed or invalid input. |
| `unauthenticated` | `401` | Missing or invalid Bearer token. |
| `forbidden` | `403` | Token is valid but not allowed for this organization or resource. |
| `not_found` | `404` | Resource does not exist, or belongs to another organization. |
| `conflict` | `409` | State or idempotency conflict. |
| `internal_error` | `500` | Unexpected server error. Quote `request_id` when reporting. |

#### Per-organization subdomain

Each organization is assigned a slug at onboarding and gets a dedicated subdomain:

```
{customer-slug}.confidential.ai
```

All instances are addressable as:

```
{instance-name}.{customer-slug}.confidential.ai
```

Example:

```
4k9p2xq7.acme.confidential.ai
```

#### Instance names

Instances are identified by an auto-generated `name` scoped to your organization.

- **Format:** 8-character lowercase alphanumeric string (e.g. `4k9p2xq7`).
- **Uniqueness:** Names are unique within an organization.
- **Reuse:** Names are not reused for at least 30 days after termination, so a stored reference cannot silently point at a different instance.
- **Custom names:** Customer-supplied instance names are not currently supported.

## Need help?

[Contact us](mailto:hello@confidential.ai) for access, support, or feature requests.
