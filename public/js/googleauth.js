(function () {
    'use strict';

    function boot() {
        const root = document.getElementById('googleauth-login');
        if (!root || root.dataset.initialized === '1') {
            return;
        }

        if (root.dataset.languageReload === '1') {
            window.location.reload();
            return;
        }

        root.dataset.initialized = '1';
        const button = root.querySelector('[data-googleauth-button]');
        const error = root.querySelector('[data-googleauth-error]');
        const messages = {
            unavailable: root.dataset.msgUnavailable,
            missing: root.dataset.msgMissing,
            initialize: root.dataset.msgInitialize,
            load: root.dataset.msgLoad,
        };

        function showError(message) {
            if (error) {
                error.textContent = message || messages.unavailable;
            }
        }

        function submitCredential(response) {
            if (!response || !response.credential) {
                showError(messages.missing);
                return;
            }

            const form = document.createElement('form');
            form.method = 'post';
            form.action = root.dataset.callback;
            form.hidden = true;

            const fields = {
                credential: response.credential,
                _glpi_csrf_token: root.dataset.csrf,
            };
            Object.keys(fields).forEach(function (name) {
                const input = document.createElement('input');
                input.type = 'hidden';
                input.name = name;
                input.value = fields[name];
                form.appendChild(input);
            });

            document.body.appendChild(form);
            form.submit();
        }

        function initialize() {
            if (!window.google || !google.accounts || !google.accounts.id) {
                return false;
            }

            try {
                google.accounts.id.initialize({
                    client_id: root.dataset.clientId,
                    callback: submitCredential,
                    nonce: root.dataset.nonce,
                    hd: root.dataset.domain,
                    auto_select: false,
                });
                button.textContent = '';
                google.accounts.id.renderButton(button, {
                    theme: 'outline',
                    size: 'large',
                    type: 'standard',
                    shape: 'rectangular',
                    text: 'signin_with',
                    width: 300,
                    locale: root.dataset.googleLocale,
                });
                return true;
            } catch (exception) {
                showError(messages.unavailable);
                return true;
            }
        }

        if (initialize()) {
            return;
        }

        const source = 'https://accounts.google.com/gsi/client?hl='
            + encodeURIComponent(root.dataset.googleLocale);
        let script = document.querySelector('script[data-googleauth-gsi]');
        if (!script) {
            script = document.createElement('script');
            script.src = source;
            script.async = true;
            script.defer = true;
            script.dataset.googleauthGsi = '1';
            (document.head || document.documentElement).appendChild(script);
        }

        script.addEventListener('load', function () {
            if (!initialize()) {
                showError(messages.initialize);
            }
        }, {once: true});
        script.addEventListener('error', function () {
            showError(messages.load);
        }, {once: true});
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot, {once: true});
    } else {
        boot();
    }
}());
