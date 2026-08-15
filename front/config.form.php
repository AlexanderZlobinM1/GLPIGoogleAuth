<?php

/**
 * Google Auth for GLPI
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

declare(strict_types=1);

include '../../../inc/includes.php';

Session::checkRight('config', UPDATE);

global $CFG_GLPI;

if (isset($_POST['update'])) {
    $clientId = trim((string) ($_POST['client_id'] ?? ''));
    $domain = strtolower(trim((string) ($_POST['hosted_domain'] ?? '')));
    $adminEmail = strtolower(trim((string) ($_POST['admin_email'] ?? '')));
    $adminProfile = (int) ($_POST['admin_profile_id'] ?? 0);
    $viewerProfile = (int) ($_POST['viewer_profile_id'] ?? 0);

    $errors = [];
    if (!preg_match('/^[0-9]+-[a-z0-9_-]+\.apps\.googleusercontent\.com$/i', $clientId)) {
        $errors[] = 'Введите корректный Google Web Client ID.';
    }
    if (!preg_match('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/', $domain)) {
        $errors[] = 'Введите корректный домен Google Workspace.';
    }
    if (filter_var($adminEmail, FILTER_VALIDATE_EMAIL) === false || !str_ends_with($adminEmail, '@' . $domain)) {
        $errors[] = 'Email администратора должен принадлежать указанному домену.';
    }
    if ($adminProfile <= 0 || $viewerProfile <= 0) {
        $errors[] = 'Выберите профили администратора и пользователей.';
    }

    if ($errors === []) {
        Config::setConfigurationValues(PLUGIN_GOOGLEAUTH_CONFIG_CONTEXT, [
            'client_id'         => $clientId,
            'hosted_domain'     => $domain,
            'admin_email'       => $adminEmail,
            'admin_profile_id'  => $adminProfile,
            'viewer_profile_id' => $viewerProfile,
        ]);
        plugin_googleauth_apply_core_settings();
        plugin_googleauth_sync_rules(plugin_googleauth_get_config());
        Session::addMessageAfterRedirect('Google Auth настроен.', true, INFO);
        Html::redirect($_SERVER['REQUEST_URI']);
    }

    Session::addMessagesAfterRedirect($errors, false, ERROR);
}

$config = plugin_googleauth_get_config();
$origin = rtrim((string) $CFG_GLPI['url_base'], '/');

Html::header('Google Auth', $_SERVER['PHP_SELF'], 'config', 'plugins');

echo '<div class="container-xl"><div class="card"><div class="card-header">';
echo '<h2 class="card-title">Google Auth</h2></div><div class="card-body">';
echo '<p>Вход через Google Identity Services с серверной проверкой подписи ID-токена. Локальный вход GLPI остаётся доступным.</p>';
echo '<div class="alert alert-info"><strong>Authorized JavaScript origin:</strong><br><code>'
    . htmlspecialchars($origin, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')
    . '</code><br><small>Redirect URI для этого режима не требуется.</small></div>';
echo '<form method="post" action="' . htmlspecialchars($_SERVER['REQUEST_URI'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '">';
echo Html::hidden('_glpi_csrf_token', ['value' => Session::getNewCSRFToken()]);

$fields = [
    'client_id'     => ['Google Web Client ID', (string) $config['client_id']],
    'hosted_domain' => ['Google Workspace domain', (string) $config['hosted_domain']],
    'admin_email'   => ['Administrator email', (string) $config['admin_email']],
];
foreach ($fields as $name => [$label, $value]) {
    echo '<div class="mb-3"><label class="form-label" for="' . $name . '">'
        . htmlspecialchars($label, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</label>';
    echo '<input class="form-control" type="text" id="' . $name . '" name="' . $name . '" value="'
        . htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '" required></div>';
}

echo '<div class="row"><div class="col-md-6 mb-3"><label class="form-label">Administrator profile</label>';
Profile::dropdown(['name' => 'admin_profile_id', 'value' => (int) $config['admin_profile_id']]);
echo '</div><div class="col-md-6 mb-3"><label class="form-label">Default domain-user profile</label>';
Profile::dropdown(['name' => 'viewer_profile_id', 'value' => (int) $config['viewer_profile_id']]);
echo '</div></div>';

echo '<button class="btn btn-primary" type="submit" name="update" value="1">Сохранить и применить правила</button>';
echo '</form></div></div></div>';

Html::footer();

