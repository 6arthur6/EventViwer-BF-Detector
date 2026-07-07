# Security Policy

## Supported Versions

This project is still in development.

Only the latest version in the `main` branch is currently supported with security fixes.

| Version / Branch | Supported |
| ---------------- | --------- |
| main             | Yes       |
| dev              | No        |
| older versions   | No        |

## Reporting a Vulnerability

If you find a security problem in this project, please do not open a public issue with sensitive details.

Instead, report it privately to the project maintainer.

When reporting a vulnerability, include as much information as possible, such as:

- what the problem is
- how it can be reproduced
- what file or feature is affected
- possible impact
- screenshots or logs, if useful

I will try to review the report and respond as soon as possible.

## Security Notes

This project reads Windows Security events, so some files or logs may contain sensitive information, such as:

- usernames
- hostnames
- internal IP addresses
- login failure details

Do not commit real `events.json` files or real `alerts.json` files to the repository.

Use example files with fake data when sharing the project publicly.
