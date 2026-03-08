# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| 1.0.x   | :x:                |

## Reporting a Vulnerability

We take security seriously at KWTCyberWatch. If you discover a security vulnerability, please follow responsible disclosure:

### Do NOT

- Open a public GitHub issue
- Share the vulnerability publicly before it's fixed
- Exploit the vulnerability beyond what's necessary for verification

### Do

1. **Email**: Send details to **security@kwtcyberwatch.com**
2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 5 business days
- **Resolution Timeline**: Depends on severity
  - Critical: Within 7 days
  - High: Within 14 days
  - Medium: Within 30 days
  - Low: Next release cycle

### After Reporting

1. We'll confirm receipt and begin investigation
2. We'll work with you to understand the issue
3. We'll develop and test a fix
4. We'll release the fix and credit you (if desired)
5. We'll publish a security advisory if appropriate

## Security Best Practices for Users

- **Never** commit credentials or API keys to the repository
- Use environment variables for sensitive configuration
- Keep dependencies updated (Dependabot is enabled)
- Run the application behind a reverse proxy in production
- Use strong, unique passwords for the dashboard
- Change default demo credentials in production deployments

## Dependency Security

This project uses GitHub Dependabot for automated dependency vulnerability scanning and updates. Security alerts are reviewed and addressed promptly.
