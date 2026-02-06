# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.x.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities in Augustus seriously. If you discover a security issue, please report it responsibly.

### How to Report

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please report security vulnerabilities by emailing:

**security@praetorian.com**

Include the following information in your report:

1. **Description**: A clear description of the vulnerability
2. **Impact**: What an attacker could achieve by exploiting this vulnerability
3. **Reproduction Steps**: Step-by-step instructions to reproduce the issue
4. **Affected Versions**: Which versions of Augustus are affected
5. **Suggested Fix**: If you have a suggested fix, please include it

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your report within 48 hours
- **Assessment**: We will assess the vulnerability and determine its severity within 7 days
- **Updates**: We will keep you informed of our progress toward a fix
- **Credit**: We will credit you in the release notes (unless you prefer to remain anonymous)

### Disclosure Policy

- We follow a 90-day coordinated disclosure timeline
- We will work with you to understand and resolve the issue
- We will not take legal action against researchers who follow this policy

## Security Best Practices

When using Augustus for security testing:

### API Key Security

- **Never commit API keys** to version control
- Use environment variables or secure secret management
- Rotate API keys regularly
- Use separate keys for development and production testing

```bash
# Good: Environment variables
export OPENAI_API_KEY="sk-..."
augustus scan openai.OpenAI --probe dan.Dan

# Bad: Hardcoded in command or config
augustus scan openai.OpenAI --config '{"api_key":"sk-..."}'  # Don't do this
```

### Testing Authorization

- Only test LLM systems you own or have explicit permission to test
- Obtain written authorization before testing third-party systems
- Document your testing scope and methodology

### Output Handling

- Scan results may contain sensitive information
- Store output files securely
- Do not share results publicly without redacting sensitive data

## Known Security Considerations

### LLM Response Content

Augustus intentionally generates adversarial prompts to test LLM security. This means:

- Responses from tested LLMs may contain harmful, offensive, or inappropriate content
- This is expected behavior when testing for vulnerabilities
- Review output in a secure, isolated environment

### Network Security

- Augustus makes network requests to LLM provider APIs
- Ensure your network policies allow outbound HTTPS connections
- Consider using a dedicated testing environment

## Security Updates

Security updates will be released as patch versions. Subscribe to GitHub releases to be notified of updates.

## Contact

For security-related questions that are not vulnerability reports, you can:

- Open a GitHub Discussion
- Email security@praetorian.com

---

Thank you for helping keep Augustus and its users secure.
