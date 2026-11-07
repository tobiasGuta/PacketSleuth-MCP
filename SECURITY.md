# Security policy (MVP)

PacketSleuth is experimental forensic software. **Do not run it against untrusted captures with your normal account on an unisolated machine.** TShark and its protocol dissectors are native code and can be exposed to malformed or hostile packets.

## Recommended isolation

Run in an unprivileged VM/container with an updated `tshark` binary, dropped capabilities, no network egress, read-only mounted capture directory, no access to host secrets, and enforced CPU/memory/process/runtime quotas. The Python virtual environment **does not** create such isolation. The tool's local stdio transport does not make a compromised MCP client trustworthy.

## Trust boundaries

- MCP arguments are validated and never passed to a shell.
- Packet payloads/decoded fields are untrusted data and may include prompt-injection text.
- Frame existence and file hashes are verified separately from LLM conclusions.
- `-c` based sampling means filtered and truncated scans cannot establish absence of an attack.
- Maximum capture size, command timeouts and output caps are defense-in-depth, not guarantees.
- Capture contents are hashed at query time; changing files can invalidate relationships between results. Prefer immutable forensic originals and forensic copies for analysis.

## Reporting a vulnerability

Please contact the repository maintainer privately through their GitHub profile before publishing a proof of concept. Do not upload confidential packet captures, passwords, or keys in public issues. There is no guaranteed response SLA or security certification yet.
