<?php

/**
 * Google Auth for GLPI
 *
 * The verification flow is adapted from Sales Snap's Mautic GoogleAuthBundle.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

declare(strict_types=1);

namespace GlpiPlugin\Googleauth;

final class GoogleIdTokenVerifier
{
    private const JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';
    private const JWKS_CACHE_TTL = 3600;
    private const MAX_TOKEN_BYTES = 16384;

    /**
     * @return array<string, mixed>
     */
    public static function verify(
        string $idToken,
        string $clientId,
        string $hostedDomain,
        string $expectedNonce
    ): array {
        $token = trim($idToken);
        $clientId = trim($clientId);
        $hostedDomain = strtolower(trim($hostedDomain));
        $expectedNonce = trim($expectedNonce);

        if (
            $token === ''
            || strlen($token) > self::MAX_TOKEN_BYTES
            || $clientId === ''
            || $hostedDomain === ''
            || $expectedNonce === ''
        ) {
            throw new \RuntimeException('invalid_token');
        }

        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new \RuntimeException('invalid_token');
        }

        $header = self::jsonDecode(self::base64UrlDecode($parts[0]));
        $payload = self::jsonDecode(self::base64UrlDecode($parts[1]));

        if (($header['alg'] ?? null) !== 'RS256' || empty($header['kid'])) {
            throw new \RuntimeException('invalid_token');
        }

        $key = self::findJwk((string) $header['kid']);
        $pem = self::jwkToPem($key);
        $signature = self::base64UrlDecode($parts[2]);

        if (openssl_verify($parts[0] . '.' . $parts[1], $signature, $pem, OPENSSL_ALGO_SHA256) !== 1) {
            throw new \RuntimeException('invalid_token');
        }

        self::validateClaims($payload, $clientId, $hostedDomain, $expectedNonce);
        return $payload;
    }

    /**
     * @return array<string, mixed>
     */
    private static function jsonDecode(string $json): array
    {
        $decoded = json_decode($json, true, 32, JSON_THROW_ON_ERROR);
        if (!is_array($decoded)) {
            throw new \RuntimeException('invalid_token');
        }

        return $decoded;
    }

    /**
     * @param array<string, mixed> $claims
     */
    private static function validateClaims(
        array $claims,
        string $clientId,
        string $hostedDomain,
        string $expectedNonce
    ): void {
        $now = time();
        $exp = (int) ($claims['exp'] ?? 0);
        if ($exp < ($now - 60) || $exp > ($now + 7200)) {
            throw new \RuntimeException('invalid_token');
        }

        if (isset($claims['iat']) && (int) $claims['iat'] > ($now + 60)) {
            throw new \RuntimeException('invalid_token');
        }

        if (isset($claims['nbf']) && (int) $claims['nbf'] > ($now + 60)) {
            throw new \RuntimeException('invalid_token');
        }

        $issuer = trim((string) ($claims['iss'] ?? ''));
        if (!in_array($issuer, ['https://accounts.google.com', 'accounts.google.com'], true)) {
            throw new \RuntimeException('invalid_token');
        }

        $audience = $claims['aud'] ?? null;
        $audienceValid = is_array($audience)
            ? in_array($clientId, $audience, true)
            : hash_equals($clientId, (string) $audience);
        if (!$audienceValid) {
            throw new \RuntimeException('invalid_token');
        }

        if (isset($claims['azp']) && !hash_equals($clientId, (string) $claims['azp'])) {
            throw new \RuntimeException('invalid_token');
        }

        if (!hash_equals($expectedNonce, (string) ($claims['nonce'] ?? ''))) {
            throw new \RuntimeException('invalid_state');
        }

        if (trim((string) ($claims['sub'] ?? '')) === '') {
            throw new \RuntimeException('invalid_token');
        }

        $email = strtolower(trim((string) ($claims['email'] ?? '')));
        if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            throw new \RuntimeException('email_missing');
        }

        $emailVerified = $claims['email_verified'] ?? false;
        if (!($emailVerified === true || strtolower((string) $emailVerified) === 'true')) {
            throw new \RuntimeException('email_unverified');
        }

        $tokenDomain = strtolower(trim((string) ($claims['hd'] ?? '')));
        $emailDomain = strtolower((string) substr(strrchr($email, '@') ?: '', 1));
        if (
            !hash_equals($hostedDomain, $tokenDomain)
            || !hash_equals($hostedDomain, $emailDomain)
        ) {
            throw new \RuntimeException('domain_denied');
        }
    }

    /**
     * @return array<string, mixed>
     */
    private static function findJwk(string $kid): array
    {
        foreach ([false, true] as $forceRefresh) {
            $jwks = self::loadJwks($forceRefresh);
            foreach (($jwks['keys'] ?? []) as $key) {
                if (is_array($key) && hash_equals($kid, (string) ($key['kid'] ?? ''))) {
                    return $key;
                }
            }
        }

        throw new \RuntimeException('invalid_token');
    }

    /**
     * @return array<string, mixed>
     */
    private static function loadJwks(bool $forceRefresh): array
    {
        $cachePath = self::cachePath();
        if (
            !$forceRefresh
            && is_file($cachePath)
            && (int) filemtime($cachePath) >= (time() - self::JWKS_CACHE_TTL)
        ) {
            $cached = file_get_contents($cachePath);
            if (is_string($cached) && $cached !== '') {
                try {
                    return self::jsonDecode($cached);
                } catch (\Throwable) {
                    // Refresh malformed or partially written cache files.
                }
            }
        }

        $jwks = self::downloadJwks();
        if (!isset($jwks['keys']) || !is_array($jwks['keys']) || $jwks['keys'] === []) {
            throw new \RuntimeException('invalid_token');
        }

        self::writeCache($cachePath, json_encode($jwks, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
        return $jwks;
    }

    private static function cachePath(): string
    {
        $base = defined('GLPI_CACHE_DIR') ? GLPI_CACHE_DIR : sys_get_temp_dir();
        return rtrim((string) $base, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'googleauth-jwks.json';
    }

    private static function writeCache(string $path, string $body): void
    {
        $temporary = $path . '.' . bin2hex(random_bytes(6)) . '.tmp';
        if (file_put_contents($temporary, $body, LOCK_EX) === false) {
            return;
        }

        @chmod($temporary, 0600);
        if (!@rename($temporary, $path)) {
            @unlink($temporary);
        }
    }

    /**
     * @return array<string, mixed>
     */
    private static function downloadJwks(): array
    {
        $headers = [
            'Accept: application/json',
            'User-Agent: glpi-google-auth/1.0',
        ];

        if (function_exists('curl_init')) {
            $handle = curl_init(self::JWKS_URL);
            curl_setopt_array($handle, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HTTPHEADER     => $headers,
                CURLOPT_CONNECTTIMEOUT => 5,
                CURLOPT_TIMEOUT        => 10,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
            ]);
            $body = curl_exec($handle);
            $code = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
            curl_close($handle);

            if (is_string($body) && $body !== '' && strlen($body) <= 1048576 && $code >= 200 && $code < 300) {
                return self::jsonDecode($body);
            }
        }

        $context = stream_context_create([
            'http' => [
                'method'        => 'GET',
                'header'        => implode("\r\n", $headers) . "\r\n",
                'timeout'       => 10,
                'ignore_errors' => false,
            ],
            'ssl' => [
                'verify_peer'      => true,
                'verify_peer_name' => true,
            ],
        ]);
        $body = @file_get_contents(self::JWKS_URL, false, $context, 0, 1048576);
        if (!is_string($body) || $body === '') {
            throw new \RuntimeException('jwks_unavailable');
        }

        return self::jsonDecode($body);
    }

    private static function jwkToPem(array $jwk): string
    {
        if (($jwk['kty'] ?? '') !== 'RSA' || empty($jwk['n']) || empty($jwk['e'])) {
            throw new \RuntimeException('invalid_token');
        }

        $modulus = self::base64UrlDecode((string) $jwk['n']);
        $exponent = self::base64UrlDecode((string) $jwk['e']);
        $rsaPublicKey = self::asn1Sequence(
            self::asn1Integer($modulus) . self::asn1Integer($exponent)
        );
        $algorithmIdentifier = hex2bin('300d06092a864886f70d0101010500');
        if ($algorithmIdentifier === false) {
            throw new \RuntimeException('invalid_token');
        }

        $subjectPublicKeyInfo = self::asn1Sequence(
            $algorithmIdentifier . self::asn1BitString($rsaPublicKey)
        );

        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($subjectPublicKeyInfo), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }

    private static function asn1Integer(string $value): string
    {
        $value = ltrim($value, "\x00");
        if ($value === '') {
            $value = "\x00";
        }
        if (ord($value[0]) > 0x7f) {
            $value = "\x00" . $value;
        }

        return "\x02" . self::asn1Length(strlen($value)) . $value;
    }

    private static function asn1Sequence(string $value): string
    {
        return "\x30" . self::asn1Length(strlen($value)) . $value;
    }

    private static function asn1BitString(string $value): string
    {
        $value = "\x00" . $value;
        return "\x03" . self::asn1Length(strlen($value)) . $value;
    }

    private static function asn1Length(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }

        $out = '';
        while ($length > 0) {
            $out = chr($length & 0xff) . $out;
            $length >>= 8;
        }

        return chr(0x80 | strlen($out)) . $out;
    }

    private static function base64UrlDecode(string $value): string
    {
        $remainder = strlen($value) % 4;
        if ($remainder !== 0) {
            $value .= str_repeat('=', 4 - $remainder);
        }

        $decoded = base64_decode(strtr($value, '-_', '+/'), true);
        if ($decoded === false) {
            throw new \RuntimeException('invalid_token');
        }

        return $decoded;
    }
}

