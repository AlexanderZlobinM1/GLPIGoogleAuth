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

function plugin_googleauth_resolve_glpi_locale(?string $acceptLanguage = null): string
{
    global $CFG_GLPI;

    $hadHeader = array_key_exists('HTTP_ACCEPT_LANGUAGE', $_SERVER);
    $previousHeader = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? null;
    if ($acceptLanguage !== null) {
        $_SERVER['HTTP_ACCEPT_LANGUAGE'] = $acceptLanguage;
    }

    try {
        $locale = Session::getPreferredLanguage();
    } finally {
        if ($acceptLanguage !== null) {
            if ($hadHeader) {
                $_SERVER['HTTP_ACCEPT_LANGUAGE'] = $previousHeader;
            } else {
                unset($_SERVER['HTTP_ACCEPT_LANGUAGE']);
            }
        }
    }

    return isset($CFG_GLPI['languages'][$locale]) ? $locale : 'en_GB';
}

function plugin_googleauth_get_message_locale(string $glpiLocale): string
{
    $language = strtolower((string) preg_split('/[_@-]/', $glpiLocale, 2)[0]);

    return match ($language) {
        'de', 'es', 'fr', 'ru' => $language,
        'sr'                    => 'sr-Latn',
        default                 => 'en',
    };
}

function plugin_googleauth_get_browser_language_tag(string $glpiLocale): string
{
    global $CFG_GLPI;

    $languageTag = (string) ($CFG_GLPI['languages'][$glpiLocale][2] ?? '');
    return $languageTag !== '' ? str_replace('_', '-', $languageTag) : str_replace('_', '-', $glpiLocale);
}

/**
 * @return array<string, string>
 */
function plugin_googleauth_get_login_messages(string $locale): array
{
    $messages = [
        'en' => [
            'brand'                 => 'NEWLOOK SERVICE DESK',
            'title'                 => 'Employee sign-in',
            'hint'                  => 'Google Workspace accounts from @%s only',
            'loading'               => 'Loading Google…',
            'login_failed'          => 'Google sign-in failed. Check your account and try again.',
            'unavailable'           => 'Google sign-in is temporarily unavailable.',
            'missing_credential'    => 'Google did not return sign-in data. Please try again.',
            'initialization_failed' => 'Could not initialize Google sign-in.',
            'load_failed'           => 'Could not load Google sign-in.',
        ],
        'de' => [
            'brand'                 => 'NEWLOOK SERVICE DESK',
            'title'                 => 'Anmeldung für Mitarbeitende',
            'hint'                  => 'Nur Google-Workspace-Konten der Domain @%s',
            'loading'               => 'Google wird geladen…',
            'login_failed'          => 'Google-Anmeldung fehlgeschlagen. Prüfen Sie Ihr Konto und versuchen Sie es erneut.',
            'unavailable'           => 'Die Google-Anmeldung ist vorübergehend nicht verfügbar.',
            'missing_credential'    => 'Google hat keine Anmeldedaten zurückgegeben. Versuchen Sie es erneut.',
            'initialization_failed' => 'Die Google-Anmeldung konnte nicht initialisiert werden.',
            'load_failed'           => 'Die Google-Anmeldung konnte nicht geladen werden.',
        ],
        'es' => [
            'brand'                 => 'NEWLOOK SERVICE DESK',
            'title'                 => 'Acceso para empleados',
            'hint'                  => 'Solo cuentas de Google Workspace del dominio @%s',
            'loading'               => 'Cargando Google…',
            'login_failed'          => 'No se pudo iniciar sesión con Google. Comprueba tu cuenta e inténtalo de nuevo.',
            'unavailable'           => 'El inicio de sesión con Google no está disponible temporalmente.',
            'missing_credential'    => 'Google no devolvió los datos de acceso. Inténtalo de nuevo.',
            'initialization_failed' => 'No se pudo inicializar el inicio de sesión con Google.',
            'load_failed'           => 'No se pudo cargar el inicio de sesión con Google.',
        ],
        'fr' => [
            'brand'                 => 'NEWLOOK SERVICE DESK',
            'title'                 => 'Connexion des employés',
            'hint'                  => 'Comptes Google Workspace du domaine @%s uniquement',
            'loading'               => 'Chargement de Google…',
            'login_failed'          => 'Échec de la connexion Google. Vérifiez votre compte et réessayez.',
            'unavailable'           => 'La connexion Google est temporairement indisponible.',
            'missing_credential'    => 'Google n’a renvoyé aucune donnée de connexion. Réessayez.',
            'initialization_failed' => 'Impossible d’initialiser la connexion Google.',
            'load_failed'           => 'Impossible de charger la connexion Google.',
        ],
        'ru' => [
            'brand'                 => 'NEWLOOK SERVICE DESK',
            'title'                 => 'Вход для сотрудников',
            'hint'                  => 'Только аккаунты Google Workspace @%s',
            'loading'               => 'Загрузка Google…',
            'login_failed'          => 'Вход через Google не выполнен. Проверьте аккаунт и повторите.',
            'unavailable'           => 'Вход через Google временно недоступен.',
            'missing_credential'    => 'Google не вернул данные входа. Повторите попытку.',
            'initialization_failed' => 'Не удалось инициализировать вход через Google.',
            'load_failed'           => 'Не удалось загрузить вход через Google.',
        ],
        'sr-Latn' => [
            'brand'                 => 'NEWLOOK SERVICE DESK',
            'title'                 => 'Prijava za zaposlene',
            'hint'                  => 'Samo Google Workspace nalozi sa domena @%s',
            'loading'               => 'Google se učitava…',
            'login_failed'          => 'Prijava preko Google naloga nije uspela. Proverite nalog i pokušajte ponovo.',
            'unavailable'           => 'Prijava preko Google naloga trenutno nije dostupna.',
            'missing_credential'    => 'Google nije vratio podatke za prijavu. Pokušajte ponovo.',
            'initialization_failed' => 'Nije moguće pokrenuti prijavu preko Google naloga.',
            'load_failed'           => 'Nije moguće učitati prijavu preko Google naloga.',
        ],
    ];

    return $messages[$locale] ?? $messages['en'];
}

/**
 * @return array<string, string>
 */
function plugin_googleauth_get_config_messages(string $locale): array
{
    $messages = [
        'en' => [
            'invalid_client'        => 'Enter a valid Google Web Client ID.',
            'invalid_domain'        => 'Enter a valid Google Workspace domain.',
            'invalid_admin'         => 'The administrator email must belong to the configured domain.',
            'invalid_profiles'      => 'Select the administrator and user profiles.',
            'saved'                 => 'Google Auth has been configured.',
            'description'           => 'Google Identity Services sign-in with server-side ID-token signature verification. Local GLPI sign-in remains available.',
            'origin'                => 'Authorized JavaScript origin',
            'redirect_not_required' => 'A redirect URI is not required for this flow.',
            'client_id'             => 'Google Web Client ID',
            'domain'                => 'Google Workspace domain',
            'admin_email'           => 'Administrator email',
            'admin_profile'         => 'Administrator profile',
            'viewer_profile'        => 'Default domain-user profile',
            'save'                  => 'Save and apply rules',
        ],
        'de' => [
            'invalid_client'        => 'Geben Sie eine gültige Google Web Client-ID ein.',
            'invalid_domain'        => 'Geben Sie eine gültige Google-Workspace-Domain ein.',
            'invalid_admin'         => 'Die Administrator-E-Mail muss zur konfigurierten Domain gehören.',
            'invalid_profiles'      => 'Wählen Sie die Profile für Administratoren und Benutzer aus.',
            'saved'                 => 'Google Auth wurde konfiguriert.',
            'description'           => 'Anmeldung über Google Identity Services mit serverseitiger Signaturprüfung des ID-Tokens. Die lokale GLPI-Anmeldung bleibt verfügbar.',
            'origin'                => 'Autorisierter JavaScript-Ursprung',
            'redirect_not_required' => 'Für diesen Ablauf ist keine Weiterleitungs-URI erforderlich.',
            'client_id'             => 'Google Web Client-ID',
            'domain'                => 'Google-Workspace-Domain',
            'admin_email'           => 'Administrator-E-Mail',
            'admin_profile'         => 'Administratorprofil',
            'viewer_profile'        => 'Standardprofil für Domain-Benutzer',
            'save'                  => 'Speichern und Regeln anwenden',
        ],
        'es' => [
            'invalid_client'        => 'Introduce un ID de cliente web de Google válido.',
            'invalid_domain'        => 'Introduce un dominio de Google Workspace válido.',
            'invalid_admin'         => 'El correo del administrador debe pertenecer al dominio configurado.',
            'invalid_profiles'      => 'Selecciona los perfiles de administrador y de usuario.',
            'saved'                 => 'Google Auth se ha configurado.',
            'description'           => 'Inicio de sesión con Google Identity Services y verificación de la firma del token de ID en el servidor. El acceso local de GLPI sigue disponible.',
            'origin'                => 'Origen de JavaScript autorizado',
            'redirect_not_required' => 'Este flujo no requiere un URI de redirección.',
            'client_id'             => 'ID de cliente web de Google',
            'domain'                => 'Dominio de Google Workspace',
            'admin_email'           => 'Correo del administrador',
            'admin_profile'         => 'Perfil de administrador',
            'viewer_profile'        => 'Perfil predeterminado de usuarios del dominio',
            'save'                  => 'Guardar y aplicar las reglas',
        ],
        'fr' => [
            'invalid_client'        => 'Saisissez un ID client Web Google valide.',
            'invalid_domain'        => 'Saisissez un domaine Google Workspace valide.',
            'invalid_admin'         => 'L’adresse e-mail de l’administrateur doit appartenir au domaine configuré.',
            'invalid_profiles'      => 'Sélectionnez les profils administrateur et utilisateur.',
            'saved'                 => 'Google Auth a été configuré.',
            'description'           => 'Connexion Google Identity Services avec vérification côté serveur de la signature du jeton d’identité. La connexion locale GLPI reste disponible.',
            'origin'                => 'Origine JavaScript autorisée',
            'redirect_not_required' => 'Aucun URI de redirection n’est nécessaire pour ce flux.',
            'client_id'             => 'ID client Web Google',
            'domain'                => 'Domaine Google Workspace',
            'admin_email'           => 'E-mail de l’administrateur',
            'admin_profile'         => 'Profil administrateur',
            'viewer_profile'        => 'Profil par défaut des utilisateurs du domaine',
            'save'                  => 'Enregistrer et appliquer les règles',
        ],
        'ru' => [
            'invalid_client'        => 'Введите корректный Google Web Client ID.',
            'invalid_domain'        => 'Введите корректный домен Google Workspace.',
            'invalid_admin'         => 'Email администратора должен принадлежать указанному домену.',
            'invalid_profiles'      => 'Выберите профили администратора и пользователей.',
            'saved'                 => 'Google Auth настроен.',
            'description'           => 'Вход через Google Identity Services с серверной проверкой подписи ID-токена. Локальный вход GLPI остаётся доступным.',
            'origin'                => 'Разрешённый источник JavaScript',
            'redirect_not_required' => 'Redirect URI для этого режима не требуется.',
            'client_id'             => 'Google Web Client ID',
            'domain'                => 'Домен Google Workspace',
            'admin_email'           => 'Email администратора',
            'admin_profile'         => 'Профиль администратора',
            'viewer_profile'        => 'Профиль пользователей домена по умолчанию',
            'save'                  => 'Сохранить и применить правила',
        ],
        'sr-Latn' => [
            'invalid_client'        => 'Unesite važeći Google Web Client ID.',
            'invalid_domain'        => 'Unesite važeći Google Workspace domen.',
            'invalid_admin'         => 'E-adresa administratora mora pripadati podešenom domenu.',
            'invalid_profiles'      => 'Izaberite profile administratora i korisnika.',
            'saved'                 => 'Google Auth je podešen.',
            'description'           => 'Prijava preko Google Identity Services uz serversku proveru potpisa ID tokena. Lokalna GLPI prijava ostaje dostupna.',
            'origin'                => 'Ovlašćeno JavaScript poreklo',
            'redirect_not_required' => 'Redirect URI nije potreban za ovaj način prijave.',
            'client_id'             => 'Google Web Client ID',
            'domain'                => 'Google Workspace domen',
            'admin_email'           => 'E-adresa administratora',
            'admin_profile'         => 'Profil administratora',
            'viewer_profile'        => 'Podrazumevani profil korisnika domena',
            'save'                  => 'Sačuvaj i primeni pravila',
        ],
    ];

    return $messages[$locale] ?? $messages['en'];
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
    $glpiLocale = plugin_googleauth_resolve_glpi_locale();
    $messageLocale = plugin_googleauth_get_message_locale($glpiLocale);
    $browserLanguage = plugin_googleauth_get_browser_language_tag($glpiLocale);
    $messages = plugin_googleauth_get_login_messages($messageLocale);
    $error = isset($_GET['googleauth_error']) ? $messages['login_failed'] : '';
    $languageReload = (string) ($_SESSION['glpilanguage'] ?? '') !== $glpiLocale;

    if ($languageReload && isset($CFG_GLPI['languages'][$glpiLocale])) {
        $_SESSION['glpilanguage'] = $glpiLocale;
        $_SESSION['glpi_dropdowntranslations'] = DropdownTranslation::getAvailableTranslations($glpiLocale);
    }

    $attributes = [
        'id'          => 'googleauth-login',
        'class'       => 'googleauth-login',
        'lang'           => $browserLanguage,
        'data-client-id' => (string) $config['client_id'],
        'data-domain'    => (string) $config['hosted_domain'],
        'data-nonce'     => $nonce,
        'data-callback'  => $callback,
        'data-csrf'      => Session::getNewCSRFToken(),
        'data-error'     => $error,
        'data-language-reload' => $languageReload ? '1' : '0',
        'data-google-locale'    => str_replace('-', '_', $browserLanguage),
        'data-msg-unavailable'  => $messages['unavailable'],
        'data-msg-missing'      => $messages['missing_credential'],
        'data-msg-initialize'   => $messages['initialization_failed'],
        'data-msg-load'         => $messages['load_failed'],
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
    echo '<div class="googleauth-login__brand">'
        . htmlspecialchars($messages['brand'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')
        . '</div>';
    echo '<p class="googleauth-login__title">'
        . htmlspecialchars($messages['title'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')
        . '</p>';
    echo '<p class="googleauth-login__hint">'
        . htmlspecialchars(
            sprintf($messages['hint'], (string) $config['hosted_domain']),
            ENT_QUOTES | ENT_SUBSTITUTE,
            'UTF-8'
        )
        . '</p>';
    echo '<div class="googleauth-login__button" data-googleauth-button>'
        . htmlspecialchars($messages['loading'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')
        . '</div>';
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
        'language'                                => 'en_GB',
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
