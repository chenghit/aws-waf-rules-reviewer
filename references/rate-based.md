## Rate-based Rules

### Characteristics
- There is a delay from threshold breach to rule activation — rate-based rules do not take effect instantaneously
- Evaluation window options: 60s (1 min), 120s (2 min), 300s (5 min, default), 600s (10 min)
- Rate limit threshold: minimum 10 requests per evaluation window, no upper bound specified
- Action: any rule action except Allow

### What rate-based rules can't do
- With a scope-down, the action applies only to requests that match the scope-down, not to all requests from the IP. Only IP aggregation without a scope-down blocks everything from the IP
- Detection usually takes about 20–30 seconds after the threshold is crossed
- A `UriPath` aggregation key counts each IP + path pair separately; there is no way to count distinct paths per IP, so path enumeration can't be detected directly
- WAF inspects requests only, not origin responses (ATP/ACFP excepted), so 404/403 counts can't be a rule condition
- Log-driven 4xx auto-blocking (Athena/Lambda writing an IP set) acts after minutes and is costly to run, so it doesn't help against burst scanning. Security Automations for AWS WAF, which offers this, retires in December 2026

### Challenge action on rate-limit rules
- For API paths: Challenge = Block (clients can't complete)
- For browser paths: legitimate users rarely exceed thresholds
- Low severity issue in DDoS context

### Native app traffic coverage
- Native app traffic that bypasses Challenge-based protections (e.g., via scope-down exclusion or because native apps cannot complete Challenge) still needs rate limiting as a defense layer
- Ensure at least one rate-based rule covers native app traffic paths without relying on Challenge as the action

### Multiple rate-based rules with overlapping scope-downs
- If a Web ACL has multiple rate-based rules, and their scope-down conditions overlap or have a containing relationship (e.g., one targets `/api/` and another targets all traffic), only the rule with the lowest threshold will ever trigger for the overlapping traffic
- The other rules are effectively redundant for that traffic
- If the intent was different rate limits for different traffic types, scope-downs should be adjusted to be mutually exclusive

