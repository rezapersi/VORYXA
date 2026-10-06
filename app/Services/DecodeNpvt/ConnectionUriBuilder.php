<?php

namespace App\Services\DecodeNpvt;

use InvalidArgumentException;

class ConnectionUriBuilder
{
    public function build(array $normalized): string
    {
        $all = $normalized['all'] ?? $normalized;

        $protocol = strtolower((string) ($all['protocol'] ?? ''));

        return match ($protocol) {
            'trojan' => $this->buildTrojan($all),
            'vless' => $this->buildVless($all),
            'vmess' => $this->buildVmess($all),
            'shadowsocks', 'ss' => $this->buildShadowsocks($all),

            default => throw new InvalidArgumentException(
                "Unsupported protocol: {$protocol}"
            ),
        };
    }

    /*
    |--------------------------------------------------------------------------
    | Trojan
    |--------------------------------------------------------------------------
    */

    private function buildTrojan(array $all): string
    {
        $password = $this->required(
            $all['password'] ?? null,
            'Trojan password'
        );

        $address = $this->required(
            $all['address'] ?? null,
            'Trojan address'
        );

        $port = (int) ($all['port'] ?? 443);

        $query = [];

        $network = strtolower((string) ($all['network'] ?? 'tcp'));

        $query['type'] = $this->normalizeNetworkForUri($network);

        /*
        |--------------------------------------------------------------------------
        | Transport
        |--------------------------------------------------------------------------
        */

        $this->appendTransportParams(
            $query,
            $network,
            $all['transport'] ?? []
        );

        /*
        |--------------------------------------------------------------------------
        | TLS / Reality
        |--------------------------------------------------------------------------
        */

        $this->appendTlsParams(
            $query,
            $all['tls'] ?? [],
            $all['security'] ?? 'none'
        );

        /*
        |--------------------------------------------------------------------------
        | URI
        |--------------------------------------------------------------------------
        */

        $uri = 'trojan://'
            . rawurlencode($password)
            . '@'
            . $this->formatAddress($address)
            . ':'
            . $port;

        $uri .= $this->buildQuery($query);

        if (!empty($all['remark'])) {
            $uri .= '#' . rawurlencode((string) $all['remark']);
        }

        return $uri;
    }

    /*
    |--------------------------------------------------------------------------
    | VLESS
    |--------------------------------------------------------------------------
    */

    private function buildVless(array $all): string
    {
        $uuid = $this->required(
            $all['id'] ?? null,
            'VLESS UUID'
        );

        $address = $this->required(
            $all['address'] ?? null,
            'VLESS address'
        );

        $port = (int) ($all['port'] ?? 443);

        $query = [];

        /*
        |--------------------------------------------------------------------------
        | Encryption
        |--------------------------------------------------------------------------
        */

        $encryption = $all['encryption'] ?? null;

        if ($encryption !== null && $encryption !== '') {
            $query['encryption'] = $encryption;
        } else {
            $query['encryption'] = 'none';
        }

        /*
        |--------------------------------------------------------------------------
        | Flow
        |--------------------------------------------------------------------------
        */

        if (!empty($all['flow'])) {
            $query['flow'] = $all['flow'];
        }

        /*
        |--------------------------------------------------------------------------
        | Transport
        |--------------------------------------------------------------------------
        */

        $network = strtolower((string) ($all['network'] ?? 'tcp'));

        $query['type'] = $this->normalizeNetworkForUri($network);

        $this->appendTransportParams(
            $query,
            $network,
            $all['transport'] ?? []
        );

        /*
        |--------------------------------------------------------------------------
        | TLS / Reality
        |--------------------------------------------------------------------------
        */

        $this->appendTlsParams(
            $query,
            $all['tls'] ?? [],
            $all['security'] ?? 'none'
        );

        /*
        |--------------------------------------------------------------------------
        | URI
        |--------------------------------------------------------------------------
        */

        $uri = 'vless://'
            . rawurlencode($uuid)
            . '@'
            . $this->formatAddress($address)
            . ':'
            . $port;

        $uri .= $this->buildQuery($query);

        if (!empty($all['remark'])) {
            $uri .= '#' . rawurlencode((string) $all['remark']);
        }

        return $uri;
    }

    /*
    |--------------------------------------------------------------------------
    | VMess
    |--------------------------------------------------------------------------
    */

    private function buildVmess(array $all): string
    {
        $address = $this->required(
            $all['address'] ?? null,
            'VMess address'
        );

        $port = (int) ($all['port'] ?? 443);

        $network = strtolower((string) ($all['network'] ?? 'tcp'));

        $tls = $all['tls'] ?? [];

        /*
        |--------------------------------------------------------------------------
        | VMess standard JSON
        |--------------------------------------------------------------------------
        */

        $json = [
            'v' => '2',

            'ps' => (string) ($all['remark'] ?? ''),

            'add' => $address,

            'port' => $port,

            'id' => (string) ($all['id'] ?? ''),

            'aid' => (int) ($all['alterId'] ?? 0),

            'scy' => (string) (
                $all['security']
                ?? 'auto'
            ),

            'net' => $this->normalizeNetworkForUri($network),

            'type' => 'none',

            'host' => '',

            'path' => '',

            'tls' => '',
        ];

        /*
        |--------------------------------------------------------------------------
        | Transport
        |--------------------------------------------------------------------------
        */

        $transport = $all['transport'] ?? [];

        switch ($network) {

            case 'ws':

                $ws = $transport['ws'] ?? [];

                $json['host'] = (string) (
                    $ws['host'] ?? ''
                );

                $json['path'] = (string) (
                    $ws['path'] ?? ''
                );

                $json['type'] = 'none';

                break;

            case 'grpc':

                $grpc = $transport['grpc'] ?? [];

                $json['path'] = (string) (
                    $grpc['serviceName'] ?? ''
                );

                $json['type'] = (string) (
                    $grpc['mode'] ?? 'gun'
                );

                break;

            case 'h2':

                $h2 = $transport['h2'] ?? [];

                $json['host'] = (string) (
                    $h2['host'] ?? ''
                );

                $json['path'] = (string) (
                    $h2['path'] ?? ''
                );

                break;

            case 'httpupgrade':

                $httpupgrade = $transport['httpupgrade'] ?? [];

                $json['host'] = (string) (
                    $httpupgrade['host'] ?? ''
                );

                $json['path'] = (string) (
                    $httpupgrade['path'] ?? ''
                );

                break;

            case 'xhttp':

                $xhttp = $transport['xhttp'] ?? [];

                $json['host'] = (string) (
                    $xhttp['host'] ?? ''
                );

                $json['path'] = (string) (
                    $xhttp['path'] ?? ''
                );

                break;
        }

        /*
        |--------------------------------------------------------------------------
        | TLS
        |--------------------------------------------------------------------------
        */

        $security = strtolower(
            (string) ($all['security'] ?? 'none')
        );

        if ($security === 'tls') {

            $json['tls'] = 'tls';

            if (!empty($tls['sni'])) {
                $json['sni'] = $tls['sni'];
            }
        } elseif ($security === 'reality') {

            /*
             * VMess Reality is uncommon.
             * Preserve security value rather than inventing fields.
             */

            $json['tls'] = 'reality';
        }

        /*
        |--------------------------------------------------------------------------
        | Encode VMess JSON
        |--------------------------------------------------------------------------
        */

        $encoded = base64_encode(
            json_encode(
                $json,
                JSON_UNESCAPED_SLASHES |
                    JSON_UNESCAPED_UNICODE
            )
        );

        return 'vmess://' . $encoded;
    }

    /*
    |--------------------------------------------------------------------------
    | Shadowsocks
    |--------------------------------------------------------------------------
    */

    private function buildShadowsocks(array $all): string
    {
        $address = $this->required(
            $all['address'] ?? null,
            'Shadowsocks address'
        );

        $port = (int) ($all['port'] ?? 443);

        // Shadowsocks uses `method` as cipher. TLS `security` is separate.
        $method = $all['method'] ?? null;

        $password = $all['password'] ?? null;

        $method = $this->required(
            $method,
            'Shadowsocks method'
        );

        $password = $this->required(
            $password,
            'Shadowsocks password'
        );

        /*
        |--------------------------------------------------------------------------
        | SIP002 userinfo
        |--------------------------------------------------------------------------
        |
        | method:password
        |
        */

        // SIP002: Base64URL-encode the raw `method:password` string.
        // Do NOT rawurlencode() before Base64 encoding.
        $userinfo = $method . ':' . $password;

        $uri = 'ss://'
            . $this->base64UrlEncode($userinfo)
            . '@'
            . $this->formatAddress($address)
            . ':'
            . $port;

        /*
        |--------------------------------------------------------------------------
        | Plugin / transport
        |--------------------------------------------------------------------------
        |
        | Some Shadowsocks sources can carry plugin information.
        | We don't invent plugin data when it doesn't exist.
        |
        */

        $query = [];

        $network = strtolower(
            (string) ($all['network'] ?? '')
        );

        if ($network !== '' && $network !== 'tcp') {
            $query['type'] = $network;
        }

        if (!empty($query)) {
            $uri .= $this->buildQuery($query);
        }

        if (!empty($all['remark'])) {
            $uri .= '#' . rawurlencode(
                (string) $all['remark']
            );
        }

        return $uri;
    }

    /*
    |--------------------------------------------------------------------------
    | Transport parameters
    |--------------------------------------------------------------------------
    */

    private function appendTransportParams(
        array &$query,
        string $network,
        array $transport
    ): void {
        switch ($network) {

            /*
            |--------------------------------------------------------------------------
            | TCP
            |--------------------------------------------------------------------------
            */

            case 'tcp':

                $tcp = $transport['tcp'] ?? [];

                if (!empty($tcp['headerType'])) {
                    $query['headerType'] = $tcp['headerType'];
                }

                if (!empty($tcp['host'])) {
                    $query['host'] = $tcp['host'];
                }

                if (!empty($tcp['path'])) {
                    $query['path'] = $tcp['path'];
                }

                break;

            /*
            |--------------------------------------------------------------------------
            | KCP
            |--------------------------------------------------------------------------
            */

            case 'kcp':

                $kcp = $transport['kcp'] ?? [];

                if (!empty($kcp['headerType'])) {
                    $query['headerType'] = $kcp['headerType'];
                }

                if (!empty($kcp['host'])) {
                    $query['host'] = $kcp['host'];
                }

                if (
                    isset($kcp['mtu']) &&
                    $kcp['mtu'] !== ''
                ) {
                    $query['mtu'] = $kcp['mtu'];
                }

                if (
                    isset($kcp['tti']) &&
                    $kcp['tti'] !== ''
                ) {
                    $query['tti'] = $kcp['tti'];
                }

                break;

            /*
            |--------------------------------------------------------------------------
            | WebSocket
            |--------------------------------------------------------------------------
            */

            case 'ws':

                $ws = $transport['ws'] ?? [];

                if (
                    isset($ws['path']) &&
                    $ws['path'] !== ''
                ) {
                    $query['path'] = $ws['path'];
                }

                if (
                    isset($ws['host']) &&
                    $ws['host'] !== ''
                ) {
                    $query['host'] = $ws['host'];
                }

                if (
                    isset($ws['enableBrowserDialer']) &&
                    $ws['enableBrowserDialer'] !== null
                ) {
                    $query['enableBrowserDialer'] =
                        $ws['enableBrowserDialer'] ? '1' : '0';
                }

                break;

            /*
            |--------------------------------------------------------------------------
            | HTTP Upgrade
            |--------------------------------------------------------------------------
            */

            case 'httpupgrade':

                $httpupgrade =
                    $transport['httpupgrade'] ?? [];

                if (!empty($httpupgrade['path'])) {
                    $query['path'] = $httpupgrade['path'];
                }

                if (!empty($httpupgrade['host'])) {
                    $query['host'] = $httpupgrade['host'];
                }

                if (!empty($httpupgrade['headerType'])) {
                    $query['headerType'] =
                        $httpupgrade['headerType'];
                }

                break;

            /*
            |--------------------------------------------------------------------------
            | XHTTP
            |--------------------------------------------------------------------------
            */

            case 'xhttp':

                $xhttp = $transport['xhttp'] ?? [];

                if (!empty($xhttp['mode'])) {
                    $query['mode'] = $xhttp['mode'];
                }

                if (!empty($xhttp['host'])) {
                    $query['host'] = $xhttp['host'];
                }

                if (!empty($xhttp['path'])) {
                    $query['path'] = $xhttp['path'];
                }

                if (
                    isset($xhttp['extra']) &&
                    $xhttp['extra'] !== null &&
                    $xhttp['extra'] !== ''
                ) {
                    $extra = $xhttp['extra'];

                    if (is_array($extra)) {
                        $extra = json_encode(
                            $extra,
                            JSON_UNESCAPED_SLASHES |
                                JSON_UNESCAPED_UNICODE
                        );
                    }

                    $query['extra'] = $extra;
                }

                break;

            /*
            |--------------------------------------------------------------------------
            | H2
            |--------------------------------------------------------------------------
            */

            case 'h2':

                $h2 = $transport['h2'] ?? [];

                if (!empty($h2['host'])) {
                    $query['host'] = $h2['host'];
                }

                if (!empty($h2['path'])) {
                    $query['path'] = $h2['path'];
                }

                if (!empty($h2['headerType'])) {
                    $query['headerType'] =
                        $h2['headerType'];
                }

                break;

            /*
            |--------------------------------------------------------------------------
            | gRPC
            |--------------------------------------------------------------------------
            */

            case 'grpc':

                $grpc = $transport['grpc'] ?? [];

                if (!empty($grpc['serviceName'])) {
                    $query['serviceName'] =
                        $grpc['serviceName'];
                }

                if (!empty($grpc['authority'])) {
                    $query['authority'] =
                        $grpc['authority'];
                }

                if (!empty($grpc['mode'])) {
                    $query['mode'] = $grpc['mode'];
                }

                break;
        }
    }

    /*
    |--------------------------------------------------------------------------
    | TLS / Reality parameters
    |--------------------------------------------------------------------------
    */

    private function appendTlsParams(
        array &$query,
        array $tls,
        string $security
    ): void {
        $security = strtolower($security);

        /*
        |--------------------------------------------------------------------------
        | No TLS
        |--------------------------------------------------------------------------
        */

        if ($security === '' || $security === 'none') {
            $query['security'] = 'none';

            return;
        }

        /*
        |--------------------------------------------------------------------------
        | TLS
        |--------------------------------------------------------------------------
        */

        if ($security === 'tls') {

            $query['security'] = 'tls';

            if (
                isset($tls['sni']) &&
                $tls['sni'] !== ''
            ) {
                $query['sni'] = $tls['sni'];
            }

            if (
                isset($tls['fingerprint']) &&
                $tls['fingerprint'] !== ''
            ) {
                $query['fp'] = $tls['fingerprint'];
            }

            if (
                isset($tls['alpn']) &&
                $tls['alpn'] !== ''
            ) {
                $alpn = $tls['alpn'];

                if (is_array($alpn)) {
                    $alpn = implode(',', $alpn);
                }

                $query['alpn'] = $alpn;
            }

            if (
                array_key_exists(
                    'allowInsecure',
                    $tls
                ) &&
                $tls['allowInsecure'] !== null
            ) {
                $value = $tls['allowInsecure']
                    ? '1'
                    : '0';

                /*
                 * Keep both because different clients
                 * use different names.
                 */

                $query['insecure'] = $value;
                $query['allowInsecure'] = $value;
            }

            if (
                !empty($tls['echConfigList'])
            ) {
                $query['echConfigList'] =
                    $tls['echConfigList'];
            }

            if (
                !empty($tls['verifyPeerCertByName'])
            ) {
                $query['verifyPeerCertByName'] =
                    $tls['verifyPeerCertByName'];
            }

            if (
                !empty($tls['certificateFingerprint'])
            ) {
                $query['certificateFingerprint'] =
                    $tls['certificateFingerprint'];
            }

            return;
        }

        /*
        |--------------------------------------------------------------------------
        | Reality
        |--------------------------------------------------------------------------
        */

        if ($security === 'reality') {

            $query['security'] = 'reality';

            $reality = $tls['reality'] ?? [];

            if (!empty($reality['sni'])) {
                $query['sni'] = $reality['sni'];
            }

            if (!empty($reality['fingerprint'])) {
                $query['fp'] =
                    $reality['fingerprint'];
            }

            if (!empty($reality['publicKey'])) {
                $query['pbk'] =
                    $reality['publicKey'];
            }

            if (
                isset($reality['shortId']) &&
                $reality['shortId'] !== ''
            ) {
                $query['sid'] =
                    $reality['shortId'];
            }

            if (
                isset($reality['spiderX']) &&
                $reality['spiderX'] !== ''
            ) {
                $query['spx'] =
                    $reality['spiderX'];
            }

            if (
                isset($reality['mldsa65Verify']) &&
                $reality['mldsa65Verify'] !== ''
            ) {
                $query['pqv'] =
                    $reality['mldsa65Verify'];
            }
        }
    }

    /*
    |--------------------------------------------------------------------------
    | Query builder
    |--------------------------------------------------------------------------
    */

    private function buildQuery(array $params): string
    {
        if (empty($params)) {
            return '';
        }

        $parts = [];

        foreach ($params as $key => $value) {

            if ($value === null) {
                continue;
            }

            if (is_bool($value)) {
                $value = $value ? '1' : '0';
            }

            if (is_array($value)) {
                $value = implode(',', $value);
            }

            $parts[] =
                rawurlencode((string) $key)
                . '='
                . rawurlencode((string) $value);
        }

        return empty($parts)
            ? ''
            : '?' . implode('&', $parts);
    }

    /*
    |--------------------------------------------------------------------------
    | Helpers
    |--------------------------------------------------------------------------
    */

    private function normalizeNetworkForUri(
        string $network
    ): string {
        return match (strtolower($network)) {
            'raw' => 'tcp',
            'websocket' => 'ws',
            'mkcp' => 'kcp',
            'splithttp' => 'xhttp',
            default => strtolower($network),
        };
    }

    /**
     * Backward-compatible alias for code that calls formatHost().
     */
    private function formatHost(string $address): string
    {
        return $this->formatAddress($address);
    }

    private function formatAddress(string $address): string
    {
        /*
         * IPv6
         */

        if (
            str_contains($address, ':') &&
            !str_starts_with($address, '[')
        ) {
            return '[' . $address . ']';
        }

        return $address;
    }

    private function required(
        mixed $value,
        string $name
    ): mixed {
        if (
            $value === null ||
            $value === ''
        ) {
            throw new InvalidArgumentException(
                "{$name} is missing."
            );
        }

        return $value;
    }

    private function base64UrlEncode(
        string $value
    ): string {
        return rtrim(
            strtr(
                base64_encode($value),
                '+/',
                '-_'
            ),
            '='
        );
    }
}
