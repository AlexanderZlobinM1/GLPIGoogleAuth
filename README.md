# Google Auth for GLPI

Google Workspace sign-in for GLPI 11, based on the server-side token verification approach used by the Sales Snap [GoogleAuthBundle](https://github.com/AlexanderZlobinM1/GoogleAuthBundle) for Mautic.

The plugin keeps GLPI's local username/password login available. New Google Workspace users can be created automatically on first sign-in and assigned a restricted profile, while one configured account receives the administrator profile.

The branded login panel and the authenticated GLPI session follow the browser's `Accept-Language` preference for English, German, Spanish, French, and Serbian (Latin). English is used for every other language.

## Security model

- Uses Google Identity Services and a Web Client ID; no client secret is stored in GLPI.
- Verifies the JWT signature against Google's JWKS.
- Validates `alg`, `kid`, `iss`, `aud`, optional `azp`, `exp`, `nbf`, `nonce`, `sub`, `email`, and `email_verified`.
- Requires both the signed `hd` claim and the email suffix to equal the configured Workspace domain.
- Uses a one-time, session-bound nonce and GLPI's CSRF token.
- Caches Google's signing keys for one hour and refreshes immediately when a new key ID appears.
- Sends only the verified email and profile fields into GLPI's native external-authentication flow.

The browser-side `hd` option is only an account-picker hint. Access control relies on the signed `hd` claim checked on the server.

## Requirements

- GLPI 11.0.x
- PHP 8.2 or newer
- PHP JSON and OpenSSL extensions
- PHP cURL or `allow_url_fopen`
- A public HTTPS GLPI origin
- A Google OAuth 2.0 Web Client ID

## Install

Place the repository in GLPI's plugin directory using the fixed directory name `googleauth`:

```bash
cd /var/www/glpi/plugins
git clone https://github.com/AlexanderZlobinM1/GLPIGoogleAuth.git googleauth
cd /var/www/glpi
sudo -u www-data php bin/console plugin:install googleauth
sudo -u www-data php bin/console plugin:activate googleauth
```

The JavaScript and CSS files live in the plugin's `public/` directory, as required by GLPI 11's secure request router. No web-server alias or symlink to the plugin source directory is required.

Open **Setup → Plugins → Google Auth → Configure** and enter:

- Google Web Client ID
- Google Workspace domain
- administrator email
- administrator profile
- default domain-user profile

Saving the form enables GLPI's native external-authentication header mapping, automatic user creation, and two managed authorization rules. Uninstalling the plugin removes only its managed rules and restores core authentication values that the plugin changed when those values have not subsequently been modified by an administrator.

## Google Cloud configuration

Create an OAuth client with application type **Web application** in Google Auth Platform. Add the exact public GLPI origin to **Authorized JavaScript origins**, for example:

```text
https://servicedesk.example.com
```

Do not add a path. This popup/callback implementation does not require an authorized redirect URI.

For an organization-only application, configure the Google Auth Platform audience as **Internal** when the Google Cloud project belongs to the same Workspace organization. The plugin still enforces the configured domain independently on every login.

## Role behavior

- The exact configured administrator email receives the selected administrator profile in the root entity.
- Other verified users from the configured domain receive the selected default profile in the root entity.
- The administrator is explicitly excluded from the default-user rule.
- Users from other domains are rejected before GLPI user creation.
- Manual GLPI users and the standard local login form remain available.

The plugin manages only rules named `Google Auth - administrator` and `Google Auth - domain viewers`.

## Credits

Copyright 2026 Sales Snap. The Google ID-token verification flow is adapted from the Sales Snap Mautic GoogleAuthBundle.

## License

GPL-3.0-or-later.
