# Security policy

Please do not publish authentication bypasses, token-validation issues, or credential exposure in a public issue before a fix is available.

Report security issues privately to the repository owner through GitHub's **Security → Report a vulnerability** function.

Supported releases are the latest tagged release on GLPI 11.0.x. Keep GLPI, PHP, OpenSSL, and this plugin updated.

Operational recommendations:

- use HTTPS only;
- keep the Google application audience Internal when possible;
- configure an exact Workspace domain, never a wildcard;
- use a read-only GLPI profile as the default domain-user profile;
- retain at least one tested local Super-Admin account for recovery;
- rate-limit the callback path at the reverse proxy;
- review GLPI login events and web-server logs.
