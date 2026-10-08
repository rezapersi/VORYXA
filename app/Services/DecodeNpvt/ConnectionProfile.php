<?php

namespace App\Services\DecodeNpvt;

use InvalidArgumentException;

class ConnectionProfile
{
    public function normalize(array $config): array
    {
        /*
        |--------------------------------------------------------------------------
        | Source containers
        |--------------------------------------------------------------------------
        */

        $rawConfig = is_array($config['raw_config'] ?? null)
            ? $config['raw_config']
            : $config;

        $rawProfile = is_array($config['raw_profile'] ?? null)
            ? $config['raw_profile']
            : [];

        $rawOutbound = is_array($config['raw_outbound'] ?? null)
            ? $config['raw_outbound']
            : [];

        $rawStream = is_array($rawOutbound['streamSettings'] ?? null)
            ? $rawOutbound['streamSettings']
            : [];

        /*
        |--------------------------------------------------------------------------
        | Protocol
        |--------------------------------------------------------------------------
        */

        $protocol = strtolower((string) (
            $config['protocol']
            ?? $rawOutbound['protocol']
            ?? ''
        ));

        if ($protocol === '') {
            $protocol = $this->detectProtocol($config, $rawProfile, $rawOutbound);
        }

        // Direct NPVT profiles use configType as the authoritative discriminator.
        // It must win over ambiguous fields such as password/method/security.
        if (empty($rawOutbound['protocol']) && isset($rawProfile['configType'])) {
            $type = (int) $rawProfile['configType'];
            $protocol = match ($type) {
                1 => 'vmess',
                3 => 'shadowsocks',
                5 => 'vless',
                6 => 'trojan',
                7 => 'socks',
                default => $protocol,
            };
        }

        /*
        |--------------------------------------------------------------------------
        | Basic fields
        |--------------------------------------------------------------------------
        */

        $remark = $this->firstValue([
            $config['name'] ?? null,
            $config['remarks'] ?? null,
            $rawProfile['remarks'] ?? null,
            $rawConfig['name'] ?? null,
        ]);

        $address = $this->firstValue([
            $config['address'] ?? null,
            $config['server'] ?? null,
            $rawProfile['server'] ?? null,
            $this->outboundAddress($rawOutbound),
            $this->vnextAddress($rawOutbound),
        ]);

        $port = $this->firstValue([
            $config['port'] ?? null,
            $config['serverPort'] ?? null,
            $rawProfile['serverPort'] ?? null,
            $this->outboundPort($rawOutbound),
            $this->vnextPort($rawOutbound),
        ]);

        /*
        |--------------------------------------------------------------------------
        | Credentials
        |--------------------------------------------------------------------------
        */

        $uuid = $this->firstValue([
            $config['uuid'] ?? null,
            $config['id'] ?? null,
            $this->outboundUuid($rawOutbound),
        ]);

        $password = $this->firstValue([
            $config['password'] ?? null,
            $rawProfile['password'] ?? null,
            $this->outboundPassword($rawOutbound),
        ]);

        $username = $this->firstValue([
            $config['username'] ?? null,
            $config['user'] ?? null,
            $rawProfile['username'] ?? null,
            $rawProfile['user'] ?? null,
        ]);

        $method = $this->firstValue([
            $config['method'] ?? null,
            $rawProfile['method'] ?? null,
            $this->outboundMethod($rawOutbound),
        ]);

        $encryption = $this->firstValue([
            $config['encryption'] ?? null,
            $this->outboundEncryption($rawOutbound),
        ]);

        $flow = $this->firstValue([
            $config['flow'] ?? null,
            $this->outboundFlow($rawOutbound),
        ]);

        // Direct NPVT profiles overload password/method depending on protocol.
        // Normalize them here so the URI builder never has to guess.
        if (!is_array($rawOutbound) || empty($rawOutbound['protocol'])) {
            switch ($protocol) {
                case 'vless':
                    $uuid = $uuid ?: $password;
                    $password = null;
                    $encryption = $encryption ?: $method ?: 'none';
                    $method = null;
                    break;

                case 'vmess':
                    $uuid = $uuid ?: $password;
                    $password = null;
                    break;

                case 'shadowsocks':
                    // password + method remain exactly as stored.
                    $uuid = null;
                    $encryption = null;
                    break;

                case 'trojan':
                    // password is the Trojan credential; method is not a cipher.
                    $uuid = null;
                    $method = null;
                    break;

                case 'socks':
                    $uuid = null;
                    $method = null;
                    $encryption = null;
                    break;
            }
        }

        /*
        |--------------------------------------------------------------------------
        | Network
        |--------------------------------------------------------------------------
        */

        $network = $this->normalizeNetwork(
            $this->firstValue([
                $config['network'] ?? null,
                $rawProfile['network'] ?? null,
                $rawStream['network'] ?? null,
            ])
        );

        /*
        |--------------------------------------------------------------------------
        | Security / TLS
        |--------------------------------------------------------------------------
        */

        $security = strtolower((string) $this->firstValue([
            $config['security'] ?? null,
            $rawProfile['security'] ?? null,
            $rawStream['security'] ?? null,
        ], 'none'));

        /*
        |--------------------------------------------------------------------------
        | Transport
        |--------------------------------------------------------------------------
        */

        $transport = $this->buildTransport(
            $network,
            $config,
            $rawProfile,
            $rawStream
        );

        /*
        |--------------------------------------------------------------------------
        | TLS
        |--------------------------------------------------------------------------
        */

        $tls = $this->buildTls(
            $security,
            $config,
            $rawProfile,
            $rawStream
        );

        /*
        |--------------------------------------------------------------------------
        | Final canonical object
        |--------------------------------------------------------------------------
        */

        $all = [
            'protocol' => $protocol,

            'remark' => $remark,

            'address' => $address !== null ? (string) $address : null,
            'port' => $port !== null ? (int) $port : null,

            'id' => $uuid,
            'password' => $password,
            'username' => $username,

            // Shadowsocks cipher/method is intentionally separate from TLS security.
            'method' => $method,

            'security' => $security,

            'encryption' => $encryption,
            'flow' => $flow,

            'network' => $network,

            'transport' => $transport,

            'tls' => $tls,

            /*
            |--------------------------------------------------------------------------
            | Protocol specific
            |--------------------------------------------------------------------------
            */

            'socks' => [
                'user' => $this->firstValue([
                    $config['user'] ?? null,
                    $config['username'] ?? null,
                ]),

                'password' => $password,
            ],

            'wireguard' => [
                'secretKey' => $this->firstValue([
                    $config['secretKey'] ?? null,
                    $config['privateKey'] ?? null,
                    $config['private_key'] ?? null,
                ]),

                'publicKey' => $this->firstValue([
                    $config['publicKey'] ?? null,
                    $config['peerPublicKey'] ?? null,
                    $config['peer_public_key'] ?? null,
                ]),

                'preSharedKey' => $this->firstValue([
                    $config['preSharedKey'] ?? null,
                    $config['pre_shared_key'] ?? null,
                ]),

                'reserved' => $config['reserved'] ?? null,

                'localAddress' => $this->firstValue([
                    $config['localAddress'] ?? null,
                    $config['local_address'] ?? null,
                ]),

                'mtu' => $config['mtu'] ?? null,
            ],

            'hysteria2' => [
                'password' => $password,

                'obfsPassword' => $this->firstValue([
                    $config['obfsPassword'] ?? null,
                    $config['obfs_password'] ?? null,
                    $rawProfile['obfsPassword'] ?? null,
                ]),

                'portHopping' => $this->firstValue([
                    $config['portHopping'] ?? null,
                    $config['port_hopping'] ?? null,
                ]),

                'portHoppingInterval' => $this->firstValue([
                    $config['portHoppingInterval'] ?? null,
                    $config['port_hopping_interval'] ?? null,
                ]),

                'bandwidthDown' => $this->firstValue([
                    $config['bandwidthDown'] ?? null,
                    $config['bandwidth_down'] ?? null,
                ]),

                'bandwidthUp' => $this->firstValue([
                    $config['bandwidthUp'] ?? null,
                    $config['bandwidth_up'] ?? null,
                ]),
            ],

            /*
            |--------------------------------------------------------------------------
            | Raw data
            |
            | Very important:
            | Never throw away source information.
            |--------------------------------------------------------------------------
            */

            'raw' => [
                'config' => $rawConfig,
                'outbound' => $rawOutbound,
                'streamSettings' => $rawStream,
                'transport' => $config['transport'] ?? null,
                'raw_profile' => $rawProfile,
                'raw_v2ray' => $config['raw_v2ray'] ?? null,
            ],
        ];

        return [
            'protocol' => $protocol,
            'all' => $all,
        ];
    }

    /*
    |--------------------------------------------------------------------------
    | TRANSPORT
    |--------------------------------------------------------------------------
    */

    private function buildTransport(
        string $network,
        array $config,
        array $profile,
        array $stream
    ): array {
        /*
         * First create the complete schema.
         * This guarantees all supported networks exist.
         */

        $transport = [
            'tcp' => [
                'headerType' => null,
                'host' => null,
                'path' => null,
            ],

            'kcp' => [
                'headerType' => null,
                'host' => null,
                'mtu' => null,
                'tti' => null,
            ],

            'ws' => [
                'host' => null,
                'path' => null,
                'enableBrowserDialer' => null,
            ],

            'httpupgrade' => [
                'headerType' => null,
                'host' => null,
                'path' => null,
            ],

            'xhttp' => [
                'mode' => null,
                'host' => null,
                'path' => null,
                'extra' => null,
            ],

            'h2' => [
                'headerType' => null,
                'host' => null,
                'path' => null,
            ],

            'grpc' => [
                'mode' => null,
                'authority' => null,
                'serviceName' => null,
            ],
        ];

        /*
        |--------------------------------------------------------------------------
        | Build generic source
        |--------------------------------------------------------------------------
        |
        | Direct NPVT profiles such as vip6 put:
        |
        | host
        | path
        | network
        |
        | directly inside raw_profile.
        |
        | Therefore profile MUST be one of our sources.
        |
        */

        $sourceTransport = is_array($config['transport'] ?? null)
            ? $config['transport']
            : [];

        $host = $this->firstValue([
            $config['host'] ?? null,
            $sourceTransport['host'] ?? null,

            $profile['host'] ?? null,
            $stream['wsSettings']['host'] ?? null,
            $stream['httpSettings']['host'] ?? null,
            $stream['httpupgradeSettings']['host'] ?? null,
            $stream['xhttpSettings']['host'] ?? null,
            $stream['splithttpSettings']['host'] ?? null,
            $stream['httpSettings']['host'] ?? null,
        ]);

        $path = $this->firstValue([
            $config['path'] ?? null,
            $sourceTransport['path'] ?? null,

            $profile['path'] ?? null,
            $stream['wsSettings']['path'] ?? null,
            $stream['httpSettings']['path'] ?? null,
            $stream['httpupgradeSettings']['path'] ?? null,
            $stream['xhttpSettings']['path'] ?? null,
            $stream['splithttpSettings']['path'] ?? null,
            $stream['httpSettings']['path'] ?? null,
        ]);

        /*
        |--------------------------------------------------------------------------
        | WS
        |--------------------------------------------------------------------------
        */

        $ws = $stream['wsSettings'] ?? [];

        $transport['ws'] = [
            'host' => $this->firstValue([
                $ws['host'] ?? null,
                $config['ws_host'] ?? null,
                $config['wsHost'] ?? null,
                $host,
            ]),

            'path' => $this->firstValue([
                $ws['path'] ?? null,
                $config['ws_path'] ?? null,
                $config['wsPath'] ?? null,
                $path,
            ]),

            'enableBrowserDialer' => $this->firstValue([
                $ws['enableBrowserDialer'] ?? null,
                $profile['enableBrowserDialer'] ?? null,
                $config['enableBrowserDialer'] ?? null,
                $sourceTransport['enableBrowserDialer'] ?? null,
            ]),
        ];

        /*
        |--------------------------------------------------------------------------
        | TCP
        |--------------------------------------------------------------------------
        */

        $tcp = $stream['tcpSettings']
            ?? $stream['rawSettings']
            ?? [];

        $tcpHeader = $tcp['header'] ?? [];

        $transport['tcp'] = [
            'headerType' => $this->firstValue([
                $tcpHeader['type'] ?? null,
                $profile['headerType'] ?? null,
                $config['headerType'] ?? null,
            ]),

            'host' => $this->firstValue([
                $tcpHeader['request']['headers']['Host'] ?? null,
                $tcpHeader['request']['headers']['host'] ?? null,
                $profile['host'] ?? null,
            ]),

            'path' => $this->firstValue([
                $tcpHeader['request']['path'][0] ?? null,
                $profile['path'] ?? null,
            ]),
        ];

        /*
        |--------------------------------------------------------------------------
        | KCP
        |--------------------------------------------------------------------------
        */

        $kcp = $stream['kcpSettings']
            ?? $stream['mkcpSettings']
            ?? [];

        $kcpHeader = $kcp['header'] ?? [];

        $transport['kcp'] = [
            'headerType' => $this->firstValue([
                $kcpHeader['type'] ?? null,
                $profile['headerType'] ?? null,
                $config['headerType'] ?? null,
            ]),

            'host' => $this->firstValue([
                $profile['host'] ?? null,
                $config['host'] ?? null,
            ]),

            'mtu' => $this->firstValue([
                $kcp['mtu'] ?? null,
                $profile['mtu'] ?? null,
                $config['mtu'] ?? null,
            ]),

            'tti' => $this->firstValue([
                $kcp['tti'] ?? null,
                $profile['tti'] ?? null,
                $config['tti'] ?? null,
            ]),
        ];

        /*
        |--------------------------------------------------------------------------
        | HTTP Upgrade
        |--------------------------------------------------------------------------
        */

        $httpUpgrade = $stream['httpupgradeSettings'] ?? [];

        $transport['httpupgrade'] = [
            'headerType' => $this->firstValue([
                $httpUpgrade['headerType'] ?? null,
                $profile['headerType'] ?? null,
                $config['headerType'] ?? null,
            ]),

            'host' => $this->firstValue([
                $httpUpgrade['host'] ?? null,
                $profile['host'] ?? null,
                $config['host'] ?? null,
            ]),

            'path' => $this->firstValue([
                $httpUpgrade['path'] ?? null,
                $profile['path'] ?? null,
                $config['path'] ?? null,
            ]),
        ];

        /*
        |--------------------------------------------------------------------------
        | XHTTP
        |--------------------------------------------------------------------------
        */

        $xhttp = $stream['xhttpSettings']
            ?? $stream['splithttpSettings']
            ?? $sourceTransport['raw']
            ?? [];

        $transport['xhttp'] = [
            'mode' => $this->firstValue([
                $xhttp['mode'] ?? null,
                $profile['mode'] ?? null,
                $config['mode'] ?? null,
                $sourceTransport['mode'] ?? null,
            ]),

            'host' => $this->firstValue([
                $xhttp['host'] ?? null,
                $profile['host'] ?? null,
                $config['host'] ?? null,
                $sourceTransport['host'] ?? null,
            ]),

            'path' => $this->firstValue([
                $xhttp['path'] ?? null,
                $profile['path'] ?? null,
                $config['path'] ?? null,
                $sourceTransport['path'] ?? null,
            ]),

            'extra' => $this->firstValue([
                $xhttp['extra'] ?? null,
                $profile['extra'] ?? null,
                $config['extra'] ?? null,
            ]),
        ];

        /*
        |--------------------------------------------------------------------------
        | H2
        |--------------------------------------------------------------------------
        */

        $h2 = $stream['httpSettings'] ?? [];

        $transport['h2'] = [
            'headerType' => $this->firstValue([
                $h2['headerType'] ?? null,
                $profile['headerType'] ?? null,
                $config['headerType'] ?? null,
            ]),

            'host' => $this->firstValue([
                $h2['host'] ?? null,
                $profile['host'] ?? null,
                $config['host'] ?? null,
            ]),

            'path' => $this->firstValue([
                $h2['path'] ?? null,
                $profile['path'] ?? null,
                $config['path'] ?? null,
            ]),
        ];

        /*
        |--------------------------------------------------------------------------
        | gRPC
        |--------------------------------------------------------------------------
        */

        $grpc = $stream['grpcSettings'] ?? [];

        $transport['grpc'] = [
            'mode' => $this->firstValue([
                $grpc['multiMode'] ?? null
                    ? 'multi'
                    : (
                        array_key_exists('multiMode', $grpc)
                        ? 'gun'
                        : null
                    ),

                $grpc['mode'] ?? null,
                $profile['mode'] ?? null,
                $config['mode'] ?? null,
            ]),

            'authority' => $this->firstValue([
                $grpc['authority'] ?? null,
                $profile['authority'] ?? null,
                $config['authority'] ?? null,
            ]),

            'serviceName' => $this->firstValue([
                $grpc['serviceName'] ?? null,
                $profile['serviceName'] ?? null,
                $config['service_name'] ?? null,
                $config['serviceName'] ?? null,
            ]),
        ];

        return $transport;
    }

    /*
    |--------------------------------------------------------------------------
    | TLS
    |--------------------------------------------------------------------------
    */

    private function buildTls(
        string $security,
        array $config,
        array $profile,
        array $stream
    ): array {
        $tlsSettings = is_array($stream['tlsSettings'] ?? null)
            ? $stream['tlsSettings']
            : [];

        $realitySettings = is_array($stream['realitySettings'] ?? null)
            ? $stream['realitySettings']
            : [];

        $sourceTls = is_array($config['tls'] ?? null)
            ? $config['tls']
            : [];

        $sourceReality = is_array($config['reality'] ?? null)
            ? $config['reality']
            : [];

        /*
        |--------------------------------------------------------------------------
        | TLS source precedence
        |--------------------------------------------------------------------------
        |
        | raw_profile is VERY important for direct NPVT configs.
        |
        */

        $sni = $this->firstValue([
            $tlsSettings['serverName'] ?? null,
            $profile['sni'] ?? null,
            $config['sni'] ?? null,
            $sourceTls['sni'] ?? null,
            $sourceTls['server_name'] ?? null,
        ]);

        $fingerprint = $this->firstValue([
            $tlsSettings['fingerprint'] ?? null,
            $profile['fingerPrint'] ?? null,
            $profile['fingerprint'] ?? null,
            $config['fingerprint'] ?? null,
            $config['fingerPrint'] ?? null,
            $sourceTls['fingerprint'] ?? null,
        ]);

        $alpn = $this->firstValue([
            $tlsSettings['alpn'] ?? null,
            $profile['alpn'] ?? null,
            $config['alpn'] ?? null,
            $sourceTls['alpn'] ?? null,
        ]);

        if (is_array($alpn)) {
            $alpn = implode(',', $alpn);
        }

        $allowInsecure = $this->firstValue([
            array_key_exists('allowInsecure', $tlsSettings)
                ? $tlsSettings['allowInsecure']
                : null,

            array_key_exists('insecure', $profile)
                ? $profile['insecure']
                : null,

            array_key_exists('allow_insecure', $config)
                ? $config['allow_insecure']
                : null,

            array_key_exists('insecure', $config)
                ? $config['insecure']
                : null,

            array_key_exists('allowInsecure', $sourceTls)
                ? $sourceTls['allowInsecure']
                : null,
            array_key_exists('allow_insecure', $sourceTls)
                ? $sourceTls['allow_insecure']
                : null,
        ]);

        /*
        |--------------------------------------------------------------------------
        | Reality
        |--------------------------------------------------------------------------
        */

        $realitySni = $this->firstValue([
            $realitySettings['serverName'] ?? null,
            $profile['sni'] ?? null,
            $config['sni'] ?? null,
        ]);

        $realityFingerprint = $this->firstValue([
            $realitySettings['fingerprint'] ?? null,
            $profile['fingerPrint'] ?? null,
            $profile['fingerprint'] ?? null,
            $config['fingerprint'] ?? null,
            $config['fingerPrint'] ?? null,
        ]);

        $publicKey = $this->firstValue([
            $realitySettings['publicKey'] ?? null,
            $profile['publicKey'] ?? null,
            $config['publicKey'] ?? null,
            $sourceReality['publicKey'] ?? null,
            $sourceReality['public_key'] ?? null,
        ]);

        $shortId = $this->firstValue([
            $realitySettings['shortId'] ?? null,
            $profile['shortId'] ?? null,
            $config['shortId'] ?? null,
            $sourceReality['shortId'] ?? null,
            $sourceReality['short_id'] ?? null,
        ]);

        $spiderX = $this->firstValue([
            $realitySettings['spiderX'] ?? null,
            $profile['spiderX'] ?? null,
            $config['spiderX'] ?? null,
            $sourceReality['spiderX'] ?? null,
            $sourceReality['spider_x'] ?? null,
        ]);

        $mldsa65Verify = $this->firstValue([
            $realitySettings['mldsa65Verify'] ?? null,
            $profile['mldsa65Verify'] ?? null,
            $config['mldsa65Verify'] ?? null,
            $sourceReality['mldsa65Verify'] ?? null,
            $sourceReality['mldsa65_verify'] ?? null,
        ]);

        return [
            'type' => $security,

            'sni' => $sni,

            'fingerprint' => $fingerprint,

            'alpn' => $alpn,

            'allowInsecure' => $allowInsecure,

            'echConfigList' => $this->firstValue([
                $tlsSettings['echConfigList'] ?? null,
                $profile['echConfigList'] ?? null,
                $config['echConfigList'] ?? null,
            ]),

            'verifyPeerCertByName' => $this->firstValue([
                $tlsSettings['verifyPeerCertByName'] ?? null,
                $profile['verifyPeerCertByName'] ?? null,
                $config['verifyPeerCertByName'] ?? null,
            ]),

            'certificateFingerprint' => $this->firstValue([
                $tlsSettings['certificateFingerprint'] ?? null,
                $profile['certificateFingerprint'] ?? null,
                $config['certificateFingerprint'] ?? null,
            ]),

            'reality' => [
                'sni' => $realitySni,
                'fingerprint' => $realityFingerprint,
                'publicKey' => $publicKey,
                'shortId' => $shortId,
                'spiderX' => $spiderX,
                'mldsa65Verify' => $mldsa65Verify,
            ],

            /*
            |--------------------------------------------------------------------------
            | Keep original TLS sources
            |--------------------------------------------------------------------------
            */

            'raw' => [
                'tlsSettings' => $tlsSettings,
                'realitySettings' => $realitySettings,
            ],
        ];
    }

    /*
    |--------------------------------------------------------------------------
    | Protocol detection
    |--------------------------------------------------------------------------
    */

    private function detectProtocol(
        array $config,
        array $profile,
        array $outbound
    ): string {
        if (!empty($outbound['protocol'])) {
            return strtolower((string) $outbound['protocol']);
        }

        if (!empty($profile['protocol'])) {
            return strtolower((string) $profile['protocol']);
        }

        if (isset($profile['configType'])) {
            return match ((int) $profile['configType']) {
                1 => 'vmess',
                3 => 'shadowsocks',
                5 => 'vless',
                6 => 'trojan',
                7 => 'socks',
                default => '',
            };
        }

        /*
        | VLESS
        */

        if (
            !empty($config['uuid']) ||
            !empty($config['id'])
        ) {
            return 'vless';
        }

        /*
        | Shadowsocks
        */

        if (
            !empty($config['method']) &&
            !empty($config['password'])
        ) {
            return 'shadowsocks';
        }

        if (
            !empty($profile['method']) &&
            !empty($profile['password'])
        ) {
            return 'shadowsocks';
        }

        /*
        | Trojan
        */

        if (
            !empty($profile['password']) &&
            !empty($profile['network']) &&
            !empty($profile['security'])
        ) {
            return 'trojan';
        }

        return '';
    }

    /*
    |--------------------------------------------------------------------------
    | Helpers
    |--------------------------------------------------------------------------
    */

    private function firstValue(array $values, mixed $default = null): mixed
    {
        foreach ($values as $value) {
            if ($value === null) {
                continue;
            }

            if (is_string($value) && trim($value) === '') {
                continue;
            }

            return $value;
        }

        return $default;
    }

    private function normalizeNetwork(?string $network): string
    {
        $network = strtolower(trim((string) $network));

        return match ($network) {
            'raw' => 'tcp',
            'tcp' => 'tcp',
            'websocket' => 'ws',
            'ws' => 'ws',
            'mkcp' => 'kcp',
            'kcp' => 'kcp',
            'httpupgrade' => 'httpupgrade',
            'xhttp' => 'xhttp',
            'splithttp' => 'xhttp',
            'h2' => 'h2',
            'http' => 'h2',
            'grpc' => 'grpc',
            default => $network ?: 'tcp',
        };
    }

    private function outboundAddress(array $outbound): ?string
    {
        return $outbound['settings']['servers'][0]['address']
            ?? $outbound['settings']['vnext'][0]['address']
            ?? null;
    }

    private function outboundPort(array $outbound): ?int
    {
        $port =
            $outbound['settings']['servers'][0]['port']
            ?? $outbound['settings']['vnext'][0]['port']
            ?? null;

        return $port !== null ? (int) $port : null;
    }

    private function vnextAddress(array $outbound): ?string
    {
        return $outbound['settings']['vnext'][0]['address'] ?? null;
    }

    private function vnextPort(array $outbound): ?int
    {
        $port = $outbound['settings']['vnext'][0]['port'] ?? null;

        return $port !== null ? (int) $port : null;
    }

    private function outboundUuid(array $outbound): ?string
    {
        return $outbound['settings']['vnext'][0]['users'][0]['id']
            ?? null;
    }

    private function outboundPassword(array $outbound): ?string
    {
        return $outbound['settings']['servers'][0]['password']
            ?? null;
    }

    private function outboundMethod(array $outbound): ?string
    {
        return $outbound['settings']['servers'][0]['method']
            ?? null;
    }

    private function outboundEncryption(array $outbound): ?string
    {
        return $outbound['settings']['vnext'][0]['users'][0]['encryption']
            ?? null;
    }

    private function outboundFlow(array $outbound): ?string
    {
        return $outbound['settings']['vnext'][0]['users'][0]['flow']
            ?? null;
    }
}

