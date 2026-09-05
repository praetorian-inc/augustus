# CLI Usage Patterns

```bash
# Basic scan
augustus scan openai.OpenAI --probe dan.Dan_11_0 --detector dan.DAN

# Glob patterns for batch runs
augustus scan anthropic.Anthropic --probes-glob "dan.*,goodside.*"

# Apply buff transformations
augustus scan openai.OpenAI --all --buff encoding.Base64

# Custom REST endpoint
augustus scan rest.Rest --probe dan.Dan_11_0 --config '{"uri":"https://api.example.com/v1/chat"}'

# Reconnaissance (first-class; --recon is repeatable and may run with or without probes)
augustus scan mcp.MCP --recon recon.MCP --config '{"endpoint":"http://localhost:8000/mcp"}'

# Recon feeding tool-surface probes in one scan (scan once, reuse everywhere)
augustus scan mcp.MCP --recon recon.MCP --probe mcptool.Injection --probe mcptool.SSRF --config '{"endpoint":"http://localhost:8000/mcp"}'

# Composed recon (recon-consumes-recon) feeding the BOLA probe; per-module settings via a recon.settings config block
augustus scan mcp.MCP --recon recon.MCP --recon recon.MCPIdentifiers --probe mcptool.BOLA --config-file bola.yaml

# MCP authentication / authorization (OWASP MCP07). UnauthenticatedAccess scores only the
# DIFFERENTIAL — credentials configured AND the credential-free session still succeeded — so
# with no credentials configured it SKIPS with a stated reason rather than firing.
augustus scan mcp.MCP \
  --probe mcptransport.UnauthenticatedAccess \
  --probe mcptool.TokenValidation --probe mcptool.FunctionAuthorization \
  --config '{"endpoint":"https://mcp.example.com/mcp","api_key":"$TOKEN","headers":{"Authorization":"Bearer $KEY"}}'

# Non-tool primitive surfaces (resources/read + prompts/get). ResourceInjection needs no
# catalog — it always sends its baseline URI payloads — but recon enriches both probes.
augustus scan mcp.MCP --recon recon.MCP \
  --probe mcpprimitive.ResourceInjection --probe mcpprimitive.PromptTemplateInjection \
  --config '{"endpoint":"http://localhost:8000/mcp"}'

# Credential exposure across every non-tool surface. Unlike the two probes above,
# ContentLeak derives ALL of its requests from the catalog, so recon (or a
# recon-capable generator) is REQUIRED: a target that cannot be enumerated is a hard
# error, never a clean pass. Note the limit of that guarantee — recon folds a failed
# list call into an empty inventory, so an enumeration that fails mid-walk arrives as
# a catalog that merely looks empty rather than as an error.
augustus scan mcp.MCP --recon recon.MCP --probe mcpprimitive.ContentLeak \
  --config '{"endpoint":"http://localhost:8000/mcp"}'
```
