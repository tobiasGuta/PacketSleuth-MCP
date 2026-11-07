# Security policy — PacketSleuth v0.3.0

PacketSleuth is experimental forensic software. It is **not** certified secure for hostile captures and does not sandbox Wireshark/TShark. A Python virtual environment isolates dependencies, **not** kernel privileges, CPU/memory usage, accessible files, or network activity.

## Safe deployment

1. Use a throwaway VM or isolated container with no external network access to parse untrusted PCAPs; drop unnecessary Linux capabilities, run as a non-root user, and enforce OS-level CPU/memory/PID/runtime limits. Never run TShark as root unless explicitly justified by your environment.
2. Restrict the `PACKETSLEUTH_CAPTURE_DIR` to a read-only directory containing only the captures you intend to analyze. Keep credentials and unrelated files out of that environment. The allowlist and magic-byte checks are defense-in-depth, not guarantees against symlink races or parser vulnerabilities.
3. Treat *all* captured strings and reconstructed payloads as attacker-controlled data. Never follow alleged instructions embedded in packet contents. The agent is responsible for treating packet content as lower-trust tool output.
4. Treat exposed credentials, personally identifying information, and private communications as sensitive. Choose an MCP client whose telemetry and model-data controls satisfy your organization.
5. Do not rely on signature hints, simple heuristics, or an AI verdict as a substitute for forensic validation.

## Failure handling and runtime configuration

MCP expected errors use explicit `ok=false` envelopes with stable error codes.
Parser failures, timeouts and exceeded output limits do not masquerade as empty
successful pages. MCP input-schema failures are normalized to `isError=true`
results containing the same structured `INVALID_INPUT` envelope as runtime
validation errors. New page cursors have HMAC integrity per server process and
are invalidated on service restart; numeric legacy offsets remain supported.
Duplicate or malformed frame identities produce parser errors instead of being
silently discarded. Frame cursors are tied to the capture SHA-256 and exact filter
scope; they cannot certify full-capture coverage. Subprocess groups are killed
and reaped on timeout or cancellation, but deployment still requires OS-level
CPU, memory, disk, and privilege restrictions. Bounded capture, scan, output and
runtime limits can be configured via the documented `PACKETSLEUTH_*` environment
variables, within hard ceilings.

DNS dissection relies on TShark PDML for per-record fields and TTLs. Unknown,
invalid, or excessively large DNS messages may have incomplete decoded records;
the tool marks that status explicitly. DNS names and answers are untrusted and
should not be executed, clicked, or resolved through external services.

## Bounded operations

MCP tools execute predetermined TShark commands without a shell or arbitrary display filters. Inputs are validated. New v0.3 tools run on bounded frame windows and compare the capture SHA-256 before/after processing; these protections do not prevent all native parser exploits, filesystem races, resource exhaustion or prompt injection. ICMP flow correlation is explicitly window-scoped and never claims that sequential Echo messages constitute a byte stream. Optional candidate concatenation is bounded, requires complete/consistent evidence, and is not proof of exfiltration. ICMP Echo extraction rejects fragmented, truncated, or ambiguous layouts; its raw payload bytes and hashes are evidence, not proof of tunneling or exfiltration. TCP reconstruction reports missing ranges, overlap conflicts, and scope limitations; it cannot prove that a full connection or application object was captured.

The service does not offer live interface capture, unrestricted code execution, arbitrary file export, external threat intelligence requests, or automatic data exfiltration. The MCP client itself may offer independent tools; audit those separately.

## Vulnerability reports

Please report potential vulnerabilities privately to the repository owner using GitHub's private vulnerability reporting (if enabled) or a private contact channel. Do not submit actual credentials or sensitive PCAP contents in public issues. Include a minimal synthetic proof of concept when possible.

There has been **no independent security audit** or formal assurance for this release.
