<?php

/**
 * Google Auth for GLPI
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

declare(strict_types=1);

use Glpi\Http\Firewall;
use Glpi\Plugin\Hooks;

define('PLUGIN_GOOGLEAUTH_VERSION', '1.0.2');
define('PLUGIN_GOOGLEAUTH_MIN_GLPI_VERSION', '11.0.0');
define('PLUGIN_GOOGLEAUTH_MAX_GLPI_VERSION', '11.0.99');

require_once __DIR__ . '/hook.php';

function plugin_init_googleauth(): void
{
    global $PLUGIN_HOOKS;

    $PLUGIN_HOOKS[Hooks::CSRF_COMPLIANT]['googleauth'] = true;

    if (!Plugin::isPluginActive('googleauth')) {
        return;
    }

    // The callback must be reachable before a GLPI user session exists. It is
    // still protected by GLPI CSRF, a one-time nonce, and Google JWT checks.
    Firewall::addPluginStrategyForLegacyScripts(
        'googleauth',
        '#^/front/callback\.php$#',
        Firewall::STRATEGY_NO_CHECK
    );

    $PLUGIN_HOOKS[Hooks::DISPLAY_LOGIN]['googleauth'] = 'plugin_googleauth_display_login';
    $PLUGIN_HOOKS[Hooks::ADD_JAVASCRIPT_ANONYMOUS_PAGE]['googleauth'] = 'js/googleauth.js';
    $PLUGIN_HOOKS[Hooks::ADD_CSS_ANONYMOUS_PAGE]['googleauth'] = 'css/googleauth.css';
    $PLUGIN_HOOKS[Hooks::CONFIG_PAGE]['googleauth'] = 'front/config.form.php';
}

/**
 * @return array<string, mixed>
 */
function plugin_version_googleauth(): array
{
    return [
        'name'         => 'Google Auth',
        'version'      => PLUGIN_GOOGLEAUTH_VERSION,
        'author'       => 'Sales Snap',
        'license'      => 'GPLv3+',
        'homepage'     => 'https://github.com/AlexanderZlobinM1/GLPIGoogleAuth',
        'requirements' => [
            'glpi' => [
                'min' => PLUGIN_GOOGLEAUTH_MIN_GLPI_VERSION,
                'max' => PLUGIN_GOOGLEAUTH_MAX_GLPI_VERSION,
            ],
            'php' => [
                'min'  => '8.2',
                'exts' => [
                    'json'    => ['required' => true],
                    'openssl' => ['required' => true],
                ],
            ],
        ],
    ];
}

function plugin_googleauth_check_prerequisites(): bool
{
    if (version_compare(GLPI_VERSION, PLUGIN_GOOGLEAUTH_MIN_GLPI_VERSION, '<')) {
        Plugin::messageIncompatible('core', PLUGIN_GOOGLEAUTH_MIN_GLPI_VERSION);
        return false;
    }

    if (!extension_loaded('openssl') || !extension_loaded('json')) {
        Plugin::messageMissingRequirement('openssl/json');
        return false;
    }

    if (!function_exists('curl_init') && !filter_var(ini_get('allow_url_fopen'), FILTER_VALIDATE_BOOL)) {
        Plugin::messageMissingRequirement('curl or allow_url_fopen');
        return false;
    }

    return true;
}

function plugin_googleauth_check_config(bool $verbose = false): bool
{
    $config = plugin_googleauth_get_config();
    $configured = plugin_googleauth_is_configured($config);

    if (!$configured && $verbose) {
        echo 'Google Auth is active but not configured; the login button remains hidden.';
    }

    // The plugin must be active before an administrator can open its config page.
    // An empty configuration is safe because the login hook renders nothing.
    return true;
}
