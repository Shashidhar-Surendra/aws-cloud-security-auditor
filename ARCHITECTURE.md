# Architecture

```text
AWS Account
    |
    | Read-only Boto3
    v
Collection / Checks
    |
    v
Standard Finding Model
    |
    +----> Risk / Severity
    |
    +----> GDPR relevance
    |
    +----> NIS2 relevance
    |
    v
Scoring
    |
    +----> JSON
    |
    +----> HTML report
```

## Design principles

1. No AWS write operations in the current implementation.
2. A failed API call is never silently interpreted as PASS.
3. Every finding contains evidence and an expected state.
4. Compliance mappings are explanatory indicators, not legal determinations.
5. Scores apply only to the configured controls.
6. HTML output escapes dynamic values to reduce report-injection risk.
7. The monitoring check is provisional and must be formally defined before the final dissertation.
