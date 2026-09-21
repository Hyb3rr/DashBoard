# External detection references

## WordPress ModSecurity Rule Set (WPRS)

- Source: https://github.com/Rev3rseSecurity/wordpress-modsecurity-ruleset
- Downloaded: 2026-09-21
- Source revision: `6bdd250e3b121f79c9b06ea48231cdada8e9dac9`
- Format: ModSecurity `.conf`, intended for WAF enforcement with OWASP CRS
- Runtime status: reference-only; Sentinel does not execute these rules and
  never blocks or modifies requests on the monitored server.
- License: no explicit license file was present in the downloaded repository;
  review upstream licensing before redistribution or production reuse.

Potential adaptation targets are WordPress login brute force, XML-RPC abuse,
user enumeration, authentication events and WordPress-specific hardening. Any
adaptation must become a reviewed Sentinel JSON rule with bounded read-only
semantics and regression tests; do not copy ModSecurity blocking actions into
the collector.
