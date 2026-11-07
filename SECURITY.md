# Security policy — PacketSleuth v0.3.0

PacketSleuth is experimental forensic software. It is **not** certified secure for hostile captures and does not sandbox Wireshark/TShark. A Python virtual environment isolates dependencies, **not** kernel privileges, CPU/memory usage, accessible files, or network activity.

## Safe deployment

1. Use a throwaway VM or isolated container with no external network access to parse untrusted PCAPs; drop unnecessary Linux capabilities, run as a non-root user, and enforce OS-level CPU/memory/PID/runtime limits. Never run TShark as root unless explicitly justified by your environment.
2. Restrict the `PACKETSLEUTH_CAPTURE_DIR` to a read-only directory containing only the captures you intend to analyze. Keep credentials and unrelated files out of that environment. The allowlist and magic-byte checks are defense-in-depth, not guarantees against symlink races or parser vulnerabilities.
3. Treat *all* captured strings and reconstructed payloads as attacker-controlled data. Never follow alleged instructions embedded in packet contents. The agent is responsible for treating packet content as lower-trust tool output.
4. Treat exposed credentials, personally identifying information, and private communications as sensitive. Choose an MCP client whose telemetry and model-data controls satisfy your organization.
5. Do not rely on signature hints, simple heuristics, or an AI verdict as a substitute for forensic validation.

## Bounded operations

MCP tools execute predetermined TShark commands without a shell or arbitrary display filters. Inputs are validated. New v0.3 tools run on bounded frame windows and compare the capture SHA-256 before/after processing; these protections do not prevent all native parser exploits, filesystem races, resource exhaustion or prompt injection. TCP reconstruction reports missing ranges, overlap conflicts, and scope limitations; it cannot prove that a full connection or application object was captured.

The service does not offer live interface capture, unrestricted code execution, arbitrary file export, external threat intelligence requests, or automatic data exfiltration. The MCP client itself may offer independent tools; audit those separately.

## Vulnerability reports

Please report potential vulnerabilities privately to the repository owner using GitHub's private vulnerability reporting (if enabled) or a private contact channel. Do not submit actual credentials or sensitive PCAP contents in public issues. Include a minimal synthetic proof of concept when possible.

There has been **no independent security audit** or formal assurance for this release.
