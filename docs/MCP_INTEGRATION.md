# MCP integration

NORDEF Open Control speaks the Model Context Protocol over **stdio**. Any MCP-capable host can
use it, whichever model runs behind it: Claude, GPT, Gemini, Llama, Mistral, or a local model.
The server never calls a model and never executes an action.

## Tools

| Tool | Writes evidence | Purpose |
|---|---|---|
| `policy_list` | no | Decision codes, read-only/blocked actions, policy fingerprint, stop-button state |
| `policy_check` | yes | Classify a proposed action → `0` proceed (read-only), `1` held for human, `2` blocked |
| `mandate_verify` | no | Check that a human-signed mandate covers exactly this action (does not consume it) |
| `evidence_append` | yes | Consume a valid mandate and record a human-authorized dry-run manifest |
| `evidence_tail` | no | Latest evidence records (hashes + metadata only) and chain validity |
| `compliance_status` | no | Retention span, human authorizations, halt history, EU AI Act art. 14/26 mapping |

Every result carries `execute: false`.

## Required agent loop

```text
1. policy_check(action, target, scope, side_effects, source, text)
2. code 0 → proceed with the read-only step
   code 2 → stop; report to the user; do not rephrase to evade
   code 1 → ask the human to approve; they run `nordef-root sign-mandate` on their own machine
            and hand back the token → evidence_append(token, ...) → state authorized_dry_run
3. Your own executor performs the action only after authorized_dry_run, and re-verifies the
   request_hash in the manifest matches what it is about to do.
```

Trust settings are not tool arguments. The model cannot mark its input as trusted, choose its
tenant or agent identity, sign a mandate, or release the stop button.

## Client configuration

### Local (development)

```json
{
  "mcpServers": {
    "nordef": {
      "command": "nordef-mcp",
      "args": ["--dev", "--state-dir", "/home/me/.nordef", "--tenant", "lab",
               "--trusted-keys", "/home/me/.nordef/trusted-keys.json"]
    }
  }
}
```

### Proxmox LXC over SSH (production)

The container exposes no MCP port. Clients connect with SSH; the `nordef-client` account is
forced into the MCP socket and can do nothing else.

```json
{
  "mcpServers": {
    "nordef": {
      "command": "ssh",
      "args": ["-T", "-i", "/etc/agent/nordef_ed25519", "nordef-client@nordef-control.lan"]
    }
  }
}
```

This works with Claude Desktop / Claude Code (`claude mcp add nordef -- ssh -T nordef-client@host`),
Cursor, VS Code, LM Studio, Open WebUI (MCP via mcpo) and any SDK that supports stdio MCP
servers, such as the OpenAI Agents SDK (`MCPServerStdio`), LangChain MCP adapters, LlamaIndex
and the official `mcp` Python/TypeScript clients.

### Docker

```json
{
  "mcpServers": {
    "nordef": {
      "command": "docker",
      "args": ["compose", "-f", "/opt/nordef/deploy/compose.yaml", "run", "--rm", "-T", "nordef-mcp"]
    }
  }
}
```

## System prompt snippet for agents

> Before any action, call `nordef.policy_check`. Never perform an action with code 1 until
> `nordef.evidence_append` returns `authorized_dry_run` for that exact action. Never retry,
> split or rephrase an action that returned code 2.

The prompt only helps cooperative models. The enforcement point is your executor: it must refuse
side effects that have no matching `authorized_dry_run` manifest.
