<?php

/**
 * Google Auth for GLPI
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

declare(strict_types=1);

const PLUGIN_GOOGLEAUTH_CONFIG_CONTEXT = 'plugin:googleauth';
const PLUGIN_GOOGLEAUTH_ADMIN_RULE = 'Google Auth - administrator';
const PLUGIN_GOOGLEAUTH_VIEWER_RULE = 'Google Auth - domain viewers';

/**
 * @return array<string, string|int>
 */
function plugin_googleauth_get_config(): array
{
    return array_merge(
        [
            'client_id'        => '',
            'hosted_domain'    => '',
            'admin_email'      => '',
            'admin_profile_id' => 4,
            'viewer_profile_id'=> 8,
        ],
        Config::getConfigurationValues(PLUGIN_GOOGLEAUTH_CONFIG_CONTEXT)
    );
}

/**
 * @param array<string, mixed> $config
 */
function plugin_googleauth_is_configured(array $config): bool
{
    return trim((string) ($config['client_id'] ?? '')) !== ''
        && trim((string) ($config['hosted_domain'] ?? '')) !== ''
        && filter_var((string) ($config['admin_email'] ?? ''), FILTER_VALIDATE_EMAIL) !== false
        && (int) ($config['admin_profile_id'] ?? 0) > 0
        && (int) ($config['viewer_profile_id'] ?? 0) > 0;
}

function plugin_googleauth_display_login(): void
{
    global $CFG_GLPI;

    $config = plugin_googleauth_get_config();
    if (!plugin_googleauth_is_configured($config)) {
        return;
    }

    $nonce = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    $_SESSION['plugin_googleauth_nonce'] = [
        'value'      => $nonce,
        'created_at' => time(),
    ];

    $root = rtrim((string) ($CFG_GLPI['root_doc'] ?? ''), '/');
    $callback = $root . '/plugins/googleauth/front/callback.php';
    $error = isset($_GET['googleauth_error']) ? 'Вход через Google не выполнен. Проверьте аккаунт и повторите.' : '';

    $attributes = [
        'id'          => 'googleauth-login',
        'class'       => 'googleauth-login',
        'data-client-id' => (string) $config['client_id'],
        'data-domain'    => (string) $config['hosted_domain'],
        'data-nonce'     => $nonce,
        'data-callback'  => $callback,
        'data-csrf'      => Session::getNewCSRFToken(),
        'data-error'     => $error,
    ];

    $htmlAttributes = '';
    foreach ($attributes as $name => $value) {
        $htmlAttributes .= sprintf(
            ' %s="%s"',
            htmlspecialchars($name, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'),
            htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')
        );
    }

    echo '<section' . $htmlAttributes . '>';
    echo '<div class="googleauth-login__brand">NewLook Service Desk</div>';
    echo '<p class="googleauth-login__title">Вход для сотрудников</p>';
    echo '<p class="googleauth-login__hint">Только аккаунты Google Workspace @'
        . htmlspecialchars((string) $config['hosted_domain'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')
        . '</p>';
    echo '<div class="googleauth-login__button" data-googleauth-button>Загрузка Google…</div>';
    echo '<div class="googleauth-login__error" data-googleauth-error aria-live="polite">'
        . htmlspecialchars($error, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')
        . '</div>';
    echo '</section>';
}

function plugin_googleauth_install(): bool
{
    $coreKeys = array_keys(plugin_googleauth_core_settings());
    $previous = Config::getConfigurationValues('core', $coreKeys);

    Config::setConfigurationValues(PLUGIN_GOOGLEAUTH_CONFIG_CONTEXT, [
        'client_id'            => '',
        'hosted_domain'        => '',
        'admin_email'          => '',
        'admin_profile_id'     => 4,
        'viewer_profile_id'    => 8,
        'previous_core_config' => json_encode($previous, JSON_UNESCAPED_SLASHES),
    ]);

    plugin_googleauth_apply_core_settings();
    return true;
}

function plugin_googleauth_uninstall(): bool
{
    $config = plugin_googleauth_get_config();
    $expected = plugin_googleauth_core_settings();
    $current = Config::getConfigurationValues('core', array_keys($expected));
    $previous = json_decode((string) ($config['previous_core_config'] ?? ''), true);

    if (is_array($previous)) {
        $restore = [];
        foreach ($expected as $name => $value) {
            if ((string) ($current[$name] ?? '') === (string) $value && array_key_exists($name, $previous)) {
                $restore[$name] = $previous[$name];
            }
        }
        if ($restore !== []) {
            Config::setConfigurationValues('core', $restore);
        }
    }

    plugin_googleauth_delete_managed_rules();
    Config::deleteConfigurationValues(
        PLUGIN_GOOGLEAUTH_CONFIG_CONTEXT,
        array_keys(Config::getConfigurationValues(PLUGIN_GOOGLEAUTH_CONFIG_CONTEXT))
    );

    return true;
}

/**
 * @return array<string, string|int>
 */
function plugin_googleauth_core_settings(): array
{
    return [
        'ssovariables_id'                         => 2,
        'existing_auth_server_field_clean_domain'=> 0,
        'email1_ssofield'                         => 'HTTP_X_GOOGLE_EMAIL',
        'firstname_ssofield'                      => 'HTTP_X_GOOGLE_GIVEN_NAME',
        'realname_ssofield'                       => 'HTTP_X_GOOGLE_FAMILY_NAME',
        'is_users_auto_add'                       => 1,
    ];
}

function plugin_googleauth_apply_core_settings(): void
{
    Config::setConfigurationValues('core', plugin_googleauth_core_settings());
}

function plugin_googleauth_delete_managed_rules(): void
{
    $rules = new RuleRight();
    foreach ($rules->find(['sub_type' => 'RuleRight']) as $id => $fields) {
        if (in_array((string) ($fields['name'] ?? ''), [PLUGIN_GOOGLEAUTH_ADMIN_RULE, PLUGIN_GOOGLEAUTH_VIEWER_RULE], true)) {
            $rules->delete(['id' => (int) $id], true);
        }
    }
}

/**
 * @param array<string, mixed> $config
 */
function plugin_googleauth_sync_rules(array $config): bool
{
    plugin_googleauth_delete_managed_rules();

    if (!plugin_googleauth_is_configured($config)) {
        return false;
    }

    $adminEmail = strtolower(trim((string) $config['admin_email']));
    $domain = strtolower(trim((string) $config['hosted_domain']));

    $adminRule = plugin_googleauth_create_rule(PLUGIN_GOOGLEAUTH_ADMIN_RULE, 1);
    plugin_googleauth_add_criterion($adminRule, 'TYPE', Rule::PATTERN_IS, Auth::EXTERNAL);
    plugin_googleauth_add_criterion($adminRule, 'LOGIN', Rule::PATTERN_IS, $adminEmail);
    plugin_googleauth_add_rule_actions($adminRule, (int) $config['admin_profile_id']);

    $viewerRule = plugin_googleauth_create_rule(PLUGIN_GOOGLEAUTH_VIEWER_RULE, 2);
    plugin_googleauth_add_criterion($viewerRule, 'TYPE', Rule::PATTERN_IS, Auth::EXTERNAL);
    plugin_googleauth_add_criterion($viewerRule, 'LOGIN', Rule::PATTERN_END, '@' . $domain);
    plugin_googleauth_add_criterion($viewerRule, 'LOGIN', Rule::PATTERN_IS_NOT, $adminEmail);
    plugin_googleauth_add_rule_actions($viewerRule, (int) $config['viewer_profile_id']);

    return true;
}

function plugin_googleauth_create_rule(string $name, int $ranking): int
{
    $rule = new RuleRight();
    $id = $rule->add([
        'name'         => $name,
        'description'  => 'Managed by the Google Auth plugin.',
        'sub_type'     => 'RuleRight',
        'match'        => 'AND',
        'condition'    => 0,
        'is_active'    => 1,
        'is_recursive' => 0,
        'ranking'      => $ranking,
    ]);

    if (!$id) {
        throw new RuntimeException('Unable to create Google Auth authorization rule.');
    }

    return (int) $id;
}

function plugin_googleauth_add_criterion(int $ruleId, string $criterion, int $condition, string|int $pattern): void
{
    $item = new RuleCriteria();
    if (!$item->add([
        'rules_id' => $ruleId,
        'criteria' => $criterion,
        'condition'=> $condition,
        'pattern'  => (string) $pattern,
    ])) {
        throw new RuntimeException('Unable to create Google Auth rule criterion.');
    }
}

function plugin_googleauth_add_rule_actions(int $ruleId, int $profileId): void
{
    foreach ([
        ['field' => 'entities_id', 'value' => 0],
        ['field' => 'profiles_id', 'value' => $profileId],
        ['field' => 'is_recursive', 'value' => 1],
    ] as $action) {
        $item = new RuleAction();
        if (!$item->add([
            'rules_id'   => $ruleId,
            'action_type'=> 'assign',
            'field'      => $action['field'],
            'value'      => (string) $action['value'],
        ])) {
            throw new RuntimeException('Unable to create Google Auth rule action.');
        }
    }
}

