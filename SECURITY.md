# Security policy

## Scope

HONEY-MIND is a **defensive, low-interaction decoy** for networks you own or are
explicitly authorised to monitor. It does not authenticate real users, execute
client commands, proxy traffic or download attacker-supplied files.

This source revision has not completed its Rust build/runtime release gates.
Do not present it as security-certified or immune to denial of service.
See [verification](docs/VERIFICATION.md) and [deployment](docs/DEPLOYMENT.md).

## Trust boundaries

- Treat all network input and recorded values as untrusted; escape them in any downstream UI.
- Configuration and the log directory must be managed by trusted operators.
- Management HTTP has no TLS/authentication. Keep it on loopback or an isolated monitoring path.
- Application limits are not a substitute for host/network isolation, egress controls and OS resource limits.
- Do not place production keys, mounted SSH agents or cloud credentials on the decoy host.
- Never enable command execution to make the emulator "more realistic" without an entirely new threat model.

## Data handling

Metadata mode suppresses raw previews, Telnet credentials and HTTP query/header values.
It is not anonymisation: IPs, URL paths and client-supplied SSH banners can be sensitive.
Full mode stores raw traffic prefixes and credentials. Access, retention, shipping and
backups must reflect that sensitivity. Memory is not securely zeroised.

Keep the log directory private; Unix files use 0600 and no-follow open flags.
Do not delete a live writer's `.lock` file, share a log path between unrelated
applications, or combine built-in rotation with copytruncate/logrotate.
Normal flush is not fsync and does not guarantee survival of power loss.

## Reporting

Use the repository's private vulnerability-reporting feature **if enabled**.
If it is unavailable, first ask the maintainer for a private channel without
posting exploit payloads, captured credentials or personal data in a public issue.
No unverified security email address or response-time SLA is asserted here.
Include the version, relevant redacted config, reproduction steps and impact.

## Operational response

Fatal writer failures stop the sensor with nonzero status. Monitor process health
outside the process (`up == 0`/service supervisor), not only its last exported counters.
A positive decoy event warrants triage; it is not conclusive attribution or proof of intrusion.
