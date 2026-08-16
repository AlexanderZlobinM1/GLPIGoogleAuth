# Changelog

## 1.0.2

- Use every locale natively supported by GLPI instead of limiting the authenticated interface to five languages.
- Add Russian to the six dedicated branded-login translations.
- Keep English only as the fallback for browser languages unsupported by GLPI.

## 1.0.1

- Browser-language detection for English, German, Spanish, French, and Serbian (Latin), including the authenticated GLPI interface.
- English fallback for unsupported browser languages.
- Persistent GLPI sessions after the request-scoped Google OAuth callback.

## 1.0.0

- Initial GLPI 11 release.
- Google Identity Services button on the GLPI login page.
- Server-side ID-token signature and claim validation.
- Exact Google Workspace domain enforcement.
- Automatic GLPI user creation and managed administrator/viewer authorization rules.
- Local GLPI login remains available.
