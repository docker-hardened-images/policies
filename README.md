<img alt="dhi-banner" src="https://github.com/user-attachments/assets/fc0ca203-3f25-4ae5-aa8e-e3918bbcc31f" />

# Docker Hardened Images Policies

This repository is the home of the [**Docker Hardened Images**](https://dhi.io) (DHI) policy definitions.
It contains the [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) policies used by the
local [`docker scout policy`](https://docs.docker.com/scout/policy/) command to evaluate whether images meet
DHI's security, supply chain, and compliance criteria.

## 🎯 Overview

[Policy evaluation](https://docs.docker.com/scout/policy/) in Docker Scout lets you define supply chain rules
for your artifacts and evaluate compliance directly from the CLI. When you run `docker scout policy`, the CLI
indexes the image into an SBOM, enriches it with CVE, VEX, and attestation data, and evaluates each configured
policy in-process against that data. No data is sent to the Scout service.

The policies in this repository encode the requirements that a Docker Hardened Image must satisfy, for example
running as a non-root user, being free of fixable critical and high vulnerabilities, and shipping signed supply
chain attestations. You can run them as-is, tune them with `--policy-config`, or use them as a starting point
for your own custom policies.

## 📁 Repository Structure

```
policies/
├── rego/               # Rego policy definitions
├── config.json         # Example policy-config for all policies
├── LICENSE.txt         # Apache 2.0 license
├── CONTRIBUTING.md     # Contribution guidelines
├── CODE_OF_CONDUCT.md  # Code of Conduct
└── SECURITY.md         # Security & vulnerability disclosure
```

### 📜 Policy Definitions (`rego/`)

Each policy is a single [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) file in the
[`rego/`](rego) directory. Every file starts with a `# METADATA` header that defines its title, description,
and presentation details, uses the `docker.scout` package, and exposes a `pass` rule that is `true` only when
no `violation` is produced.

| Policy | File | What it checks |
| --- | --- | --- |
| **No default root user** | [`default-non-root-user.rego`](rego/default-non-root-user.rego) | The image defines a non-root default `USER`. Enforced for non-dev, non-SDK, non-package variants. |
| **No fixable vulnerabilities past their remediation SLA** | [`fixable-vulnerabilities.rego`](rego/fixable-vulnerabilities.rego) | Flags packages with a fixable CVE whose remediation SLA has elapsed. SLAs vary by severity (CRITICAL/HIGH 7 days, others 30 days), with a 1-day SLA for CISA KEV-listed CVEs. |
| **No high-profile vulnerabilities** | [`high-profile-vulnerabilities.rego`](rego/high-profile-vulnerabilities.rego) | Checks a curated list of well-known, high-impact CVEs, optionally including CISA KEV. |
| **No embedded malware** | [`no-embedded-malware.rego`](rego/no-embedded-malware.rego) | Verifies the malware scan attestation is present, matches the image, and reports no infected files. |
| **No embedded secrets** | [`no-embedded-secrets.rego`](rego/no-embedded-secrets.rego) | Verifies the secret scan attestation is present, matches the image, and found no leaked secrets. |
| **No failing tests** | [`no-failing-tests.rego`](rego/no-failing-tests.rego) | Verifies the test attestation is present, matches the image, and reports no failing tests. |
| **Signed supply chain attestations** | [`signed-supply-chain-attestations.rego`](rego/signed-supply-chain-attestations.rego) | Ensures required SBOM and provenance attestations exist, match the image, and are signed by a trusted party. |
| **Unintentional shell or package manager** | [`unintentional-shell-or-package-manager.rego`](rego/unintentional-shell-or-package-manager.rego) | Flags a shell or package manager present in the image that was not explicitly declared. |
| **STIG scan score** | [`stig-scan-score.rego`](rego/stig-scan-score.rego) | Checks that FIPS images reach the required STIG scan score. Only enforced for images declaring FIPS compliance. |

## 🚀 Getting Started

### Prerequisites

- [Docker Scout](https://docs.docker.com/scout/install/) with the local `docker scout policy` command

### Use the published OCI bundle (recommended)

These policies are published as an [OCI policy bundle](https://docs.docker.com/scout/policy/local/#share-policies-as-oci-bundles)
at `dhi/policies:latest`. Pull and evaluate them against an image with `--policy-bundle`:

```bash
docker scout policy <IMAGE> --policy-bundle dhi/policies:latest
```

`--policy-bundle` is repeatable, so you can combine these policies with other bundles or your own local
policy files:

```bash
docker scout policy <IMAGE> \
  --policy-bundle dhi/policies:latest \
  --policy-file ./custom.rego
```

Authentication uses your existing Docker registry credentials, and bundles are cached by digest, so
re-running against the same bundle doesn't re-download it. A new digest (for example, after `:latest` is
re-published) is fetched automatically.

### Evaluate policies from source

To iterate on the policies in this repository directly, load them from disk with `--policy-file` (a single
policy) or `--policy-dir` (a directory, loaded recursively):

```bash
# A single policy
docker scout policy <IMAGE> --policy-file ./rego/fixable-vulnerabilities.rego

# The whole directory
docker scout policy <IMAGE> --policy-dir ./rego
```

Use `--exit-code` to fail a pipeline when any policy is not met:

```bash
docker scout policy <IMAGE> --policy-bundle dhi/policies:latest --exit-code
```

### Configure a policy

Several policies read tunable values from `data.config`, which you can override with a `--policy-config` JSON
file. Each entry is matched to a policy by its `custom.name`. This repository ships an example
[`config.json`](config.json) that lists every policy with its default configuration, so you can copy it and
adjust only what you need. For example, to only flag `CRITICAL` vulnerabilities and use a 14-day grace period
for newly disclosed CVEs:

```json
{
  "policies": [
    {
      "name": "fixable-vulnerabilities",
      "config": {
        "severities": ["CRITICAL"],
        "grace_period_days": 14
      }
    }
  ]
}
```

```bash
docker scout policy <IMAGE> \
  --policy-bundle dhi/policies:latest \
  --policy-config ./config.json
```

See the comments in each policy file for the full list of supported configuration options.

### Publish the bundle

Maintainers publish the bundle from this repository with `docker scout policy publish`:

```bash
docker scout policy publish --policy-dir ./rego dhi/policies:latest
```

## 📖 Documentation

- **[Policy Evaluation](https://docs.docker.com/scout/policy/)**: How `docker scout policy` works and the built-in policy types
- **[Evaluate policies](https://docs.docker.com/scout/policy/local/)**: Running evaluations locally, in CI, and configuring policies, including OCI bundles
- **[Contributing Guide](CONTRIBUTING.md)**: How to contribute to this project
- **[Code of Conduct](CODE_OF_CONDUCT.md)**: Community guidelines and standards
- **[License](LICENSE.txt)**: Apache 2.0 license terms

## 🤝 Contributing

We welcome contributions! Whether you're:

- Adding new policies
- Improving or fixing existing policies
- Updating documentation
- Reporting issues
- Sharing best practices

Please read our [Contributing Guide](CONTRIBUTING.md) to get started.

### Ways to Contribute

- **Policy Requests**: Open an issue to request a new policy
- **Bug Reports**: Report false positives, false negatives, or other issues with a policy
- **Enhancements**: Suggest improvements to existing policies or their configuration
- **Documentation**: Help improve guides and examples

## 🔒 Security

To report security vulnerabilities, please follow responsible disclosure practices as outlined in our
[security policy](SECURITY.md).

## 📄 License

This project is licensed under the Apache License 2.0. See [LICENSE.txt](LICENSE.txt) for details.

## 🔗 Links

- **Docker Hardened Images Catalog**: [Catalog](https://dhi.io)
- **Docker Hardened Images**: [docker.com/products/hardened-images](https://docker.com/products/hardened-images/)
- **Policy Evaluation Docs**: [docs.docker.com/scout/policy](https://docs.docker.com/scout/policy/)
- **Commercial Support**: [docker.com/support](https://docker.com/support/)
- **Issue Tracker**: [GitHub Issues](https://github.com/docker-hardened-images/policies/issues)
- **Discussions**: [GitHub Discussions](https://github.com/orgs/docker-hardened-images/discussions)

---

**Docker Hardened Images** - Building secure containers, together.
