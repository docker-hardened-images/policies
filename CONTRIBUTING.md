# Contributing to Docker Hardened Images Policies

Thank you for your interest in contributing to the Docker Hardened Images (DHI) policies! This repository is the home of the Rego policies used by the local [`docker scout policy`](https://docs.docker.com/scout/policy/) command to evaluate the compliance of Docker Hardened Images.

> **Important:** If you make any contribution to this project you agree that it is contributed under [Apache 2.0](LICENSE.txt).

## How to Contribute

### 🗣️ Participate in Discussions

**GitHub Discussions** are perfect for:
- Asking questions about policy evaluation or authoring Rego policies
- Sharing how you use DHI policies in your CI pipelines
- Discussing security and supply chain considerations
- Proposing ideas for new policies or improvements to existing ones
- Helping other community members

**Getting Started with Discussions:**
1. Browse existing [discussions](https://github.com/orgs/docker-hardened-images/discussions) to see if your topic is already covered
2. Choose the appropriate category for your discussion
3. Use clear, descriptive titles
4. Provide context and background information
5. Be respectful and constructive in your responses

### 🐛 Report Issues

**GitHub Issues** should be used for:
- Bug reports for a specific policy (e.g. a false positive or false negative)
- Requests for a new policy
- Documentation improvements
- Security vulnerabilities (following our security policy)

**Creating Quality Issues:**
1. Search existing issues to avoid duplicates
2. Use the appropriate issue template
3. Provide detailed information including:
   - Which policy is affected
   - The image (and digest) you evaluated
   - The exact `docker scout policy` command and any `--policy-config` used
   - Expected vs actual evaluation result
4. Include relevant output, SBOM/attestation details, or configuration
5. Follow up on questions from maintainers

### 🔧 Submit Pull Requests

**Pull Requests** are welcomed for:
- New policies
- Fixes and improvements to existing policies
- Documentation improvements and corrections
- Example configurations and use cases

**Creating Quality Pull Requests:**
1. **Fork and clone** the repository
2. **Create a feature branch** from `main` with a descriptive name (e.g., `policy/new-license-check`, `fix/high-profile-cve-list`)
3. **Make your changes** following the repository's style and conventions
4. **Format and lint** your Rego with [`opa fmt`](https://www.openpolicyagent.org/docs/latest/cli/#opa-fmt) and [`regal lint`](https://docs.styra.com/regal)
5. **Test your changes** by evaluating the policy against representative images with `docker scout policy`
6. **Write clear commit messages** that explain what and why
7. **Submit your PR** with:
   - A descriptive title summarizing the change
   - Details about what you changed and why
   - Reference to any related issues (e.g., "Fixes #123")
   - Example evaluation output where applicable
8. **Respond to feedback** from reviewers promptly
9. **Be patient** - reviews may take time depending on maintainer availability

**PR Best Practices:**
- Keep changes focused and atomic - one logical change per PR
- Update documentation if your changes affect user-facing behavior
- Follow existing policy style and conventions (see below)

## Authoring Policies

Every policy in this repository lives in the [`rego/`](rego) directory as a single `.rego` file and follows a common structure:

- **METADATA header**: A `# METADATA` comment block with `title`, `description`, `organizations`, `authors`, and a `custom` section (`name`, `result_type`, `not_compliant_title`, `details_order`, and optional `weight`). This drives how the policy is presented by `docker scout policy`.
- **Package**: Policies use the `package docker.scout` package and `import rego.v1`.
- **`pass` rule**: A `default pass := false` with `pass if { count(violation) == 0 }`.
- **`violation` set**: One or more `violation contains v if { ... }` rules that produce a `message` and a `detail` object whose keys match `details_order`.
- **Configuration**: Read tunable values from `data.config` via `object.get(...)` so they can be overridden with `--policy-config`. Document each option in a comment.

Use the existing policies (for example [`fixable-vulnerabilities.rego`](rego/fixable-vulnerabilities.rego) and [`high-profile-vulnerabilities.rego`](rego/high-profile-vulnerabilities.rego)) as references when writing new ones.

## Community Guidelines

### Before Contributing

1. **Read our [Code of Conduct](CODE_OF_CONDUCT.md)** - All contributions must follow our community standards
2. **Search existing content** - Check if your question/issue has already been addressed
3. **Choose the right channel** - Use discussions for questions, issues for bugs/requests

### Quality Standards

When contributing, please ensure your content:
- **Is on-topic**: Related to Docker Hardened Images and policy evaluation
- **Is well-structured**: Uses clear headings, bullet points, and formatting
- **Includes context**: Provides background information and use case details
- **Is actionable**: For issues, includes steps to reproduce or clear requirements
- **Is respectful**: Follows our community guidelines and code of conduct

### Communication Best Practices

- **Be patient**: Contributors are volunteers across different time zones
- **Be specific**: Provide clear details about the policy, image, and configuration
- **Be constructive**: Focus on solutions and improvements
- **Be helpful**: Share knowledge and assist other community members
- **Stay professional**: Maintain a respectful tone in all interactions

## Getting Help

If you need assistance with contributing:

1. **Read the documentation** - Check the [Policy Evaluation docs](https://docs.docker.com/scout/policy/), existing issues, and discussions
2. **Ask in discussions** - Use the Q&A category for contribution-related questions
3. **Be patient** - Allow time for community members and maintainers to respond
4. **Provide context** - Include details about what you're trying to contribute

## Security Considerations

When contributing:
- **Never share sensitive credentials** or production configuration details
- **Follow responsible disclosure** for security vulnerabilities (see [SECURITY.md](SECURITY.md))
- **Use example data** when sharing configurations or logs
- **Review security implications** of suggested changes or configurations

## Code of Conduct Enforcement

All contributors are expected to follow our [Code of Conduct](CODE_OF_CONDUCT.md). Violations should be reported to the community leaders, and will be addressed promptly and fairly.

---

Thank you for contributing to the Docker Hardened Images community! Your participation helps make container security more accessible and effective for everyone.
