<?php

/**
 * Google Auth for GLPI
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

declare(strict_types=1);

use GlpiPlugin\Googleauth\GoogleIdTokenVerifier;

include '../../../inc/includes.php';
require_once dirname(__DIR__) . '/src/GoogleIdTokenVerifier.php';

global $CFG_GLPI;

$root = rtrim((string) ($CFG_GLPI['root_doc'] ?? ''), '/');
$failureUrl = $root . '/index.php?noAUTO=1&googleauth_error=1';

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    Html::redirect($failureUrl);
}

$requestOrigin = trim((string) ($_SERVER['HTTP_ORIGIN'] ?? ''));
$baseParts = parse_url((string) ($CFG_GLPI['url_base'] ?? ''));
$expectedOrigin = is_array($baseParts) && isset($baseParts['scheme'], $baseParts['host'])
    ? $baseParts['scheme'] . '://' . $baseParts['host'] . (isset($baseParts['port']) ? ':' . $baseParts['port'] : '')
    : '';
if ($requestOrigin !== '' && ($expectedOrigin === '' || !hash_equals($expectedOrigin, $requestOrigin))) {
    Html::redirect($failureUrl);
}

$nonceState = $_SESSION['plugin_googleauth_nonce'] ?? null;
unset($_SESSION['plugin_googleauth_nonce']);

if (
    !is_array($nonceState)
    || !isset($nonceState['value'], $nonceState['created_at'])
    || !is_string($nonceState['value'])
    || (int) $nonceState['created_at'] < (time() - 600)
) {
    Html::redirect($failureUrl);
}

$config = plugin_googleauth_get_config();
if (!plugin_googleauth_is_configured($config)) {
    Html::redirect($failureUrl);
}

$credential = trim((string) ($_POST['credential'] ?? ''));

try {
    $claims = GoogleIdTokenVerifier::verify(
        $credential,
        (string) $config['client_id'],
        (string) $config['hosted_domain'],
        (string) $nonceState['value']
    );
} catch (Throwable $exception) {
    error_log('Google Auth login rejected: ' . $exception->getMessage());
    Html::redirect($failureUrl);
}

$email = strtolower(trim((string) ($claims['email'] ?? '')));
$_SERVER['REMOTE_USER'] = $email;
$_SERVER['HTTP_X_GOOGLE_EMAIL'] = $email;
$_SERVER['HTTP_X_GOOGLE_GIVEN_NAME'] = trim((string) ($claims['given_name'] ?? ''));
$_SERVER['HTTP_X_GOOGLE_FAMILY_NAME'] = trim((string) ($claims['family_name'] ?? ''));

$auth = new Auth();
if ($auth->login('', '', false, false)) {
    // GLPI's native header-SSO flow expects REMOTE_USER to be supplied by the
    // web server on every request and expires the session if it disappears.
    // Here the verified Google identity is intentionally request-scoped, like
    // a regular OAuth callback, so subsequent requests rely on GLPI's secure
    // session cookie instead of a persistent spoofable header.
    unset($_SESSION['glpi_remote_user']);
    Auth::redirectIfAuthenticated();
}

error_log('Google Auth token was valid, but GLPI authorization failed for ' . $email);
Html::redirect($failureUrl);
