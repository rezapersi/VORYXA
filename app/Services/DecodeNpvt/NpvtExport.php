<?php

namespace App\Services\DecodeNpvt;

use JsonException;

class NpvtExport
{
    /**
     * Extract all VPN configurations from decoded NPVT.
     */
    public function export(array $decoded): array
    {
        $configs = [];

        foreach ($decoded['blobs'] ?? [] as $blob) {
            $json = $blob['json'] ?? null;

            if (!is_array($json)) {
                continue;
            }

            $this->walk($json, $configs);
        }

        return $configs;
    }

    /**
     * Recursively find NPVT config objects.
     */
    protected function walk(mixed $data, array &$configs): void
    {
        if (!is_array($data)) {
            return;
        }

        if (
            isset($data['v2rayProfile']) &&
            is_array($data['v2rayProfile'])
        ) {
            $config = $this->extractConfig($data);

            if ($config !== null) {
                $configs[] = $config;
            }

            return;
        }

        foreach ($data as $value) {
            if (is_array($value)) {
                $this->walk($value, $configs);
            }
        }
    }

    /**
     * Extract one NPVT config.
     */
    protected function extractConfig(array $config): ?array
    {
        $profile = $config['v2rayProfile'] ?? [];

        if (!is_array($profile)) {
            return null;
        }

        /*
         * Decode v2rayJson when available.
         */
        $v2ray = null;

        if (!empty($profile['v2rayJson'])) {
            $decoded = json_decode(
                $profile['v2rayJson'],
                true
            );

            if (is_array($decoded)) {
                $v2ray = $decoded;
            }
        }

        /*
         * Find actual proxy outbound.
         */
        $outbound = null;

        if (is_array($v2ray)) {
            $outbound = $this->findProxyOutbound(
                $v2ray['outbounds'] ?? []
            );
        }

        /*
         * Determine protocol.
         */
        $protocol = null;

        if (is_array($outbound)) {
            $protocol = strtolower(
                (string) ($outbound['protocol'] ?? '')
            );
        }

        /*
         * Some NPVT files don't contain v2rayJson.
         * Detect protocol from profile structure.
         */
        if (!$protocol) {
            $protocol = $this->detectProfileProtocol(
                $config,
                $profile
            );
        }

        $result = [
            'name' => $config['name'] ?? null,

            'protocol' => $protocol ?: 'unknown',

            /*
             * Common endpoint.
             */
            'address' => null,
            'port' => null,

            /*
             * Common protocol credentials.
             */
            'uuid' => null,
            'password' => null,
            'username' => null,

            /*
             * Protocol-specific.
             */
            'method' => null,
            'encryption' => null,
            'flow' => null,
            'level' => null,
            'email' => null,

            /*
             * Transport.
             */
            'network' => null,
            'security' => 'none',

            /*
             * TLS.
             */
            'tls' => null,

            /*
             * Reality.
             */
            'reality' => null,

            /*
             * Transport-specific settings.
             */
            'transport' => null,

            /*
             * Socket settings.
             */
            'sockopt' => null,

            /*
             * Full raw data.
             */
            'raw_profile' => $profile,
            'raw_v2ray' => $v2ray,
            'raw_outbound' => $outbound,
            'raw_config' => $config,
        ];

        /*
         * If we have a real Xray outbound,
         * use the protocol-specific extractor.
         */
        if (is_array($outbound)) {

            switch ($protocol) {

                case 'vless':
                    $this->extractVless(
                        $outbound,
                        $result
                    );
                    break;

                case 'vmess':
                    $this->extractVmess(
                        $outbound,
                        $result
                    );
                    break;

                case 'trojan':
                    $this->extractTrojan(
                        $outbound,
                        $result
                    );
                    break;

                case 'shadowsocks':
                    $this->extractShadowsocks(
                        $outbound,
                        $result
                    );
                    break;

                case 'socks':
                    $this->extractSocks(
                        $outbound,
                        $result
                    );
                    break;

                case 'wireguard':
                    $this->extractWireGuard(
                        $outbound,
                        $result
                    );
                    break;

                case 'hysteria':
                case 'hysteria2':
                    $this->extractHysteria(
                        $outbound,
                        $result
                    );
                    break;

                default:
                    $this->extractGenericOutbound(
                        $outbound,
                        $result
                    );
                    break;
            }

            /*
             * Always extract streamSettings,
             * regardless of protocol.
             */
            $this->extractStreamSettings(
                $outbound,
                $result
            );
        }

        /*
         * Direct profile configs.
         *
         * Used when v2rayJson is empty.
         */
        if (!is_array($outbound)) {
            $this->extractDirectProfile(
                $config,
                $profile,
                $protocol,
                $result
            );
        }

        /*
         * Last endpoint fallback.
         */
        $this->fillEndpointFallback(
            $config,
            $profile,
            $result
        );

        return $result;
    }

    /**
     * Find the actual proxy outbound.
     */
    protected function findProxyOutbound(array $outbounds): ?array
    {
        $fallback = null;

        foreach ($outbounds as $outbound) {

            if (!is_array($outbound)) {
                continue;
            }

            $protocol = strtolower(
                (string) ($outbound['protocol'] ?? '')
            );

            $tag = strtolower(
                (string) ($outbound['tag'] ?? '')
            );

            /*
             * Best case.
             */
            if ($tag === 'proxy') {
                return $outbound;
            }

            /*
             * Don't select auxiliary outbounds.
             */
            if (in_array($protocol, [
                'freedom',
                'blackhole',
                'dns',
                'loopback',
            ], true)) {
                continue;
            }

            /*
             * Keep first usable outbound as fallback.
             */
            if ($fallback === null) {
                $fallback = $outbound;
            }
        }

        return $fallback;
    }

    /**
     * Detect protocol from NPVT profile when v2rayJson is absent.
     */
    protected function detectProfileProtocol(
        array $config,
        array $profile
    ): string {

        /*
         * Explicit protocol fields first.
         */
        foreach (
            [
                'protocol',
                'securityProtocol',
                'proxyProtocol',
                'scheme',
            ] as $key
        ) {

            if (!empty($profile[$key])) {
                $value = strtolower(
                    trim((string) $profile[$key])
                );

                if (in_array($value, [
                    'vless',
                    'vmess',
                    'trojan',
                    'shadowsocks',
                    'socks',
                    'socks5',
                    'wireguard',
                    'hysteria',
                    'hysteria2',
                ], true)) {

                    return $value === 'socks5'
                        ? 'socks'
                        : $value;
                }
            }
        }

        /*
         * WireGuard.
         */
        if (
            !empty($profile['privateKey']) ||
            !empty($profile['private_key']) ||
            !empty($profile['peerPublicKey']) ||
            !empty($profile['peer_public_key'])
        ) {
            return 'wireguard';
        }

        /*
         * Hysteria2.
         */
        if (
            array_key_exists('obfs', $profile) ||
            array_key_exists('obfsPassword', $profile) ||
            array_key_exists('obfs_password', $profile)
        ) {
            return 'hysteria2';
        }

        $password = (string) (
            $profile['password'] ?? ''
        );

        $method = (string) (
            $profile['method'] ??
            $profile['encryptionMethod'] ??
            ''
        );

        $uuid = (string) (
            $profile['id'] ??
            $profile['uuid'] ??
            ''
        );

        /*
         * VLESS / VMess UUID.
         */
        if ($this->looksLikeUuid($uuid)) {

            /*
             * VMess usually has security/method.
             */
            if (
                !empty($profile['security']) &&
                !$this->looksLikeUuid($password)
            ) {
                return 'vmess';
            }

            /*
             * VLESS commonly has UUID + encryption.
             */
            if (
                !empty($profile['encryption']) ||
                !empty($profile['flow']) ||
                !empty($profile['network'])
            ) {
                return 'vless';
            }

            /*
             * Default UUID-based profile.
             */
            return 'vless';
        }

        /*
         * Shadowsocks:
         * method + password.
         */
        if (
            $method !== '' &&
            $password !== ''
        ) {
            return 'shadowsocks';
        }

        /*
         * SOCKS.
         */
        if (
            !empty($profile['username']) ||
            !empty($profile['user'])
        ) {
            return 'socks';
        }

        /*
         * Trojan:
         * password + transport/security
         * but no SS method.
         */
        if (
            $password !== '' &&
            (
                !empty($profile['network']) ||
                !empty($profile['security']) ||
                !empty($profile['sni']) ||
                !empty($profile['serverName'])
            )
        ) {
            return 'trojan';
        }

        return 'unknown';
    }

    /**
     * VLESS
     */
    protected function extractVless(
        array $outbound,
        array &$result
    ): void {

        $settings = $outbound['settings'] ?? [];

        $vnext = $settings['vnext'][0] ?? [];

        if (!is_array($vnext)) {
            return;
        }

        $result['address'] =
            $vnext['address'] ?? null;

        $result['port'] =
            $this->normalizePort(
                $vnext['port'] ?? null
            );

        $user = $vnext['users'][0] ?? [];

        if (!is_array($user)) {
            $user = [];
        }

        $result['uuid'] =
            $user['id'] ??
            $settings['id'] ??
            $outbound['id'] ??
            null;

        $result['encryption'] =
            $user['encryption'] ??
            $settings['encryption'] ??
            $outbound['encryption'] ??
            'none';

        $result['flow'] =
            $user['flow'] ??
            $settings['flow'] ??
            null;

        $result['level'] =
            $user['level'] ??
            $settings['level'] ??
            null;

        $result['email'] =
            $user['email'] ??
            $settings['email'] ??
            null;

        /*
         * Keep all user fields.
         */
        $result['vless'] = [
            'id' => $user['id'] ?? null,
            'flow' => $user['flow'] ?? null,
            'encryption' => $user['encryption'] ?? null,
            'level' => $user['level'] ?? null,
            'email' => $user['email'] ?? null,
            'raw_user' => $user,
            'raw_vnext' => $vnext,
        ];
    }

    /**
     * VMess
     */
    protected function extractVmess(
        array $outbound,
        array &$result
    ): void {

        $settings = $outbound['settings'] ?? [];

        $vnext = $settings['vnext'][0] ?? [];

        if (!is_array($vnext)) {
            return;
        }

        $result['address'] =
            $vnext['address'] ?? null;

        $result['port'] =
            $this->normalizePort(
                $vnext['port'] ?? null
            );

        $user = $vnext['users'][0] ?? [];

        if (!is_array($user)) {
            $user = [];
        }

        $result['uuid'] =
            $user['id'] ??
            $settings['id'] ??
            $outbound['id'] ??
            null;

        $result['method'] =
            $user['security'] ??
            $settings['security'] ??
            null;

        $result['level'] =
            $user['level'] ??
            $settings['level'] ??
            null;

        $result['email'] =
            $user['email'] ??
            $settings['email'] ??
            null;

        $result['vmess'] = [
            'id' => $user['id'] ?? null,
            'security' => $user['security'] ?? null,
            'level' => $user['level'] ?? null,
            'email' => $user['email'] ?? null,
            'alterId' => $user['alterId'] ?? null,
            'experiments' => $settings['experiments'] ?? null,
            'raw_user' => $user,
            'raw_vnext' => $vnext,
        ];
    }

    /**
     * Trojan
     */
    protected function extractTrojan(
        array $outbound,
        array &$result
    ): void {

        $settings = $outbound['settings'] ?? [];

        $server = $settings['servers'][0] ?? [];

        if (!is_array($server)) {
            $server = [];
        }

        $result['address'] =
            $server['address'] ??
            $settings['address'] ??
            null;

        $result['port'] =
            $this->normalizePort(
                $server['port'] ??
                    $settings['port'] ??
                    null
            );

        $result['password'] =
            $server['password'] ??
            $settings['password'] ??
            null;

        $result['level'] =
            $server['level'] ??
            $settings['level'] ??
            null;

        $result['email'] =
            $server['email'] ??
            $settings['email'] ??
            null;

        $result['flow'] =
            $server['flow'] ??
            $settings['flow'] ??
            null;

        /*
         * Preserve the complete server object.
         */
        $result['trojan'] = [
            'password' => $server['password'] ?? null,
            'level' => $server['level'] ?? null,
            'email' => $server['email'] ?? null,
            'flow' => $server['flow'] ?? null,

            /*
             * Important:
             * Trojan may contain additional fields.
             */
            'raw_server' => $server,
            'raw_settings' => $settings,
        ];
    }

    /**
     * Shadowsocks
     */
    protected function extractShadowsocks(
        array $outbound,
        array &$result
    ): void {

        $settings = $outbound['settings'] ?? [];

        $server = $settings['servers'][0] ?? [];

        if (!is_array($server)) {
            $server = [];
        }

        $result['address'] =
            $server['address'] ??
            $settings['address'] ??
            null;

        $result['port'] =
            $this->normalizePort(
                $server['port'] ??
                    $settings['port'] ??
                    null
            );

        $result['password'] =
            $server['password'] ??
            $settings['password'] ??
            null;

        $result['method'] =
            $server['method'] ??
            $settings['method'] ??
            null;

        $result['level'] =
            $server['level'] ??
            $settings['level'] ??
            null;

        $result['email'] =
            $server['email'] ??
            $settings['email'] ??
            null;

        $result['shadowsocks'] = [
            'address' => $server['address'] ?? null,
            'port' => $server['port'] ?? null,
            'method' => $server['method'] ?? null,
            'password' => $server['password'] ?? null,
            'level' => $server['level'] ?? null,
            'email' => $server['email'] ?? null,
            'raw_server' => $server,
            'raw_settings' => $settings,
        ];
    }

    /**
     * SOCKS
     */
    protected function extractSocks(
        array $outbound,
        array &$result
    ): void {

        $settings = $outbound['settings'] ?? [];

        $server = $settings['servers'][0] ?? [];

        if (!is_array($server)) {
            $server = [];
        }

        $result['address'] =
            $server['address'] ??
            $settings['address'] ??
            null;

        $result['port'] =
            $this->normalizePort(
                $server['port'] ??
                    $settings['port'] ??
                    null
            );

        $result['username'] =
            $server['users'][0]['user'] ??
            $server['username'] ??
            $settings['username'] ??
            null;

        $result['password'] =
            $server['users'][0]['pass'] ??
            $server['password'] ??
            $settings['password'] ??
            null;

        $result['socks'] = [
            'address' => $server['address'] ?? null,
            'port' => $server['port'] ?? null,
            'users' => $server['users'] ?? [],
            'raw_server' => $server,
            'raw_settings' => $settings,
        ];
    }

    /**
     * WireGuard
     */
    protected function extractWireGuard(
        array $outbound,
        array &$result
    ): void {

        $settings = $outbound['settings'] ?? [];

        $result['wireguard'] = [
            'secretKey' =>
            $settings['secretKey'] ??
                $settings['privateKey'] ??
                null,

            'address' =>
            $settings['address'] ??
                [],

            'peers' =>
            $settings['peers'] ??
                [],

            'mtu' =>
            $settings['mtu'] ??
                null,

            'workers' =>
            $settings['workers'] ??
                null,

            'reserved' =>
            $settings['reserved'] ??
                null,

            'domainStrategy' =>
            $settings['domainStrategy'] ??
                null,

            'noKernelTun' =>
            $settings['noKernelTun'] ??
                null,

            'raw_settings' => $settings,
        ];

        /*
         * WireGuard does not use streamSettings
         * like VLESS/Trojan.
         */
        $result['address'] =
            $settings['address'][0] ??
            null;
    }

    /**
     * Hysteria / Hysteria2
     */
    protected function extractHysteria(
        array $outbound,
        array &$result
    ): void {

        $settings = $outbound['settings'] ?? [];

        $result['address'] =
            $settings['address'] ??
            null;

        $result['port'] =
            $this->normalizePort(
                $settings['port'] ?? null
            );

        $result['password'] =
            $settings['password'] ??
            null;

        $result['hysteria'] = [
            'version' =>
            $settings['version'] ??
                2,

            'address' =>
            $settings['address'] ??
                null,

            'port' =>
            $settings['port'] ??
                null,

            'password' =>
            $settings['password'] ??
                null,

            'auth' =>
            $settings['auth'] ??
                null,

            'obfs' =>
            $settings['obfs'] ??
                null,

            'obfsPassword' =>
            $settings['obfsPassword'] ??
                null,

            'up' =>
            $settings['up'] ??
                null,

            'down' =>
            $settings['down'] ??
                null,

            'upMbps' =>
            $settings['upMbps'] ??
                null,

            'downMbps' =>
            $settings['downMbps'] ??
                null,

            'recvWindowConn' =>
            $settings['recvWindowConn'] ??
                null,

            'recvWindow' =>
            $settings['recvWindow'] ??
                null,

            'disableMTUDiscovery' =>
            $settings['disableMTUDiscovery'] ??
                null,

            'pinSHA256' =>
            $settings['pinSHA256'] ??
                null,

            'fingerprint' =>
            $settings['fingerprint'] ??
                null,

            'serverName' =>
            $settings['serverName'] ??
                null,

            'raw_settings' => $settings,
        ];
    }

    /**
     * Generic outbound fallback.
     */
    protected function extractGenericOutbound(
        array $outbound,
        array &$result
    ): void {

        $settings = $outbound['settings'] ?? [];

        $result['address'] =
            $settings['address'] ??
            null;

        $result['port'] =
            $this->normalizePort(
                $settings['port'] ?? null
            );

        $result['raw_settings'] = $settings;
    }

    /**
     * Extract streamSettings completely.
     */
    protected function extractStreamSettings(
        array $outbound,
        array &$result
    ): void {

        $stream = $outbound['streamSettings'] ?? [];

        if (!is_array($stream)) {
            return;
        }

        /*
         * Network / transport.
         */
        $network =
            $stream['network'] ??
            null;

        $result['network'] = $network;

        /*
         * Security is VERY important.
         *
         * none / tls / reality
         */
        $security = strtolower(
            (string) (
                $stream['security'] ??
                'none'
            )
        );

        $result['security'] =
            $security ?: 'none';

        /*
         * TLS.
         */
        if ($security === 'tls') {

            $tls =
                $stream['tlsSettings'] ??
                [];

            if (!is_array($tls)) {
                $tls = [];
            }

            $result['tls'] = [
                'server_name' =>
                $tls['serverName'] ??
                    null,

                'alpn' =>
                $this->normalizeAlpn(
                    $tls['alpn'] ?? null
                ),

                'allow_insecure' =>
                $tls['allowInsecure'] ??
                    null,

                'fingerprint' =>
                $tls['fingerprint'] ??
                    null,

                'enable_session_resumption' =>
                $tls['enableSessionResumption'] ??
                    null,

                'disable_system_root' =>
                $tls['disableSystemRoot'] ??
                    null,

                'min_version' =>
                $tls['minVersion'] ??
                    null,

                'max_version' =>
                $tls['maxVersion'] ??
                    null,

                'cipher_suites' =>
                $tls['cipherSuites'] ??
                    null,

                'reject_unknown_sni' =>
                $tls['rejectUnknownSni'] ??
                    null,

                'curve_preferences' =>
                $tls['curvePreferences'] ??
                    null,

                'pinned_peer_cert_sha256' =>
                $tls['pinnedPeerCertSha256'] ??
                    null,

                'verify_peer_cert_by_name' =>
                $tls['verifyPeerCertByName'] ??
                    null,

                'ech_server_keys' =>
                $tls['echServerKeys'] ??
                    null,

                'ech_config_list' =>
                $tls['echConfigList'] ??
                    null,

                'ech_force_query' =>
                $tls['echForceQuery'] ??
                    null,

                'raw' => $tls,
            ];
        }

        /*
         * REALITY.
         */
        if ($security === 'reality') {

            $reality =
                $stream['realitySettings'] ??
                [];

            if (!is_array($reality)) {
                $reality = [];
            }

            $result['reality'] = [
                'show' =>
                $reality['show'] ??
                    null,

                'dest' =>
                $reality['dest'] ??
                    null,

                'xver' =>
                $reality['xver'] ??
                    null,

                'server_name' =>
                $reality['serverName'] ??
                    null,

                'fingerprint' =>
                $reality['fingerprint'] ??
                    null,

                'public_key' =>
                $reality['publicKey'] ??
                    null,

                'short_id' =>
                $reality['shortId'] ??
                    null,

                'spider_x' =>
                $reality['spiderX'] ??
                    null,

                'mldsa65_verify' =>
                $reality['mldsa65Verify'] ??
                    null,

                'raw' => $reality,
            ];
        }

        /*
         * WebSocket.
         */
        if (isset($stream['wsSettings'])) {

            $ws = $stream['wsSettings'];

            $result['transport'] = [
                'type' => 'ws',

                'host' =>
                $ws['headers']['Host'] ??
                    $ws['host'] ??
                    null,

                'path' =>
                $ws['path'] ??
                    null,

                'headers' =>
                $ws['headers'] ??
                    [],

                'heartbeat_period' =>
                $ws['heartbeatPeriod'] ??
                    null,

                'raw' => $ws,
            ];
        }

        /*
         * HTTP / H2.
         */
        if (isset($stream['httpSettings'])) {

            $http = $stream['httpSettings'];

            $result['transport'] = [
                'type' => 'http',

                'host' =>
                $http['host'] ??
                    [],

                'path' =>
                $http['path'] ??
                    null,

                'method' =>
                $http['method'] ??
                    null,

                'headers' =>
                $http['headers'] ??
                    [],

                'read_idle_timeout' =>
                $http['read_idle_timeout'] ??
                    null,

                'health_check_timeout' =>
                $http['health_check_timeout'] ??
                    null,

                'raw' => $http,
            ];
        }

        /*
         * XHTTP / SplitHTTP.
         */
        if (isset($stream['xhttpSettings'])) {

            $xhttp =
                $stream['xhttpSettings'];

            $result['transport'] = [
                'type' => 'xhttp',

                'path' =>
                $xhttp['path'] ??
                    null,

                'host' =>
                $xhttp['host'] ??
                    null,

                'mode' =>
                $xhttp['mode'] ??
                    null,

                'extra' =>
                $xhttp['extra'] ??
                    null,

                'headers' =>
                $xhttp['headers'] ??
                    [],

                'raw' => $xhttp,
            ];
        }

        /*
         * TCP / RAW.
         */
        if (
            isset($stream['tcpSettings']) ||
            isset($stream['rawSettings'])
        ) {

            $tcp =
                $stream['tcpSettings'] ??
                $stream['rawSettings'] ??
                [];

            $result['transport'] = [
                'type' => 'tcp',
                'header' =>
                $tcp['header'] ??
                    null,

                'header_type' =>
                $tcp['header']['type'] ??
                    null,

                'request' =>
                $tcp['header']['request'] ??
                    null,

                'response' =>
                $tcp['header']['response'] ??
                    null,

                'raw' => $tcp,
            ];
        }

        /*
         * gRPC.
         */
        if (isset($stream['grpcSettings'])) {

            $grpc =
                $stream['grpcSettings'];

            $result['transport'] = [
                'type' => 'grpc',

                'service_name' =>
                $grpc['serviceName'] ??
                    null,

                'multi_mode' =>
                $grpc['multiMode'] ??
                    null,

                'idle_timeout' =>
                $grpc['idle_timeout'] ??
                    null,

                'health_check_timeout' =>
                $grpc['health_check_timeout'] ??
                    null,

                'permit_without_stream' =>
                $grpc['permit_without_stream'] ??
                    null,

                'initial_windows_size' =>
                $grpc['initial_windows_size'] ??
                    null,

                'raw' => $grpc,
            ];
        }

        /*
         * HTTP Upgrade.
         */
        if (isset($stream['httpupgradeSettings'])) {

            $upgrade =
                $stream['httpupgradeSettings'];

            $result['transport'] = [
                'type' => 'httpupgrade',

                'host' =>
                $upgrade['host'] ??
                    null,

                'path' =>
                $upgrade['path'] ??
                    null,

                'headers' =>
                $upgrade['headers'] ??
                    [],

                'raw' => $upgrade,
            ];
        }

        /*
         * mKCP.
         */
        if (isset($stream['kcpSettings'])) {

            $kcp =
                $stream['kcpSettings'];

            $result['transport'] = [
                'type' => 'mkcp',

                'mtu' =>
                $kcp['mtu'] ??
                    null,

                'tti' =>
                $kcp['tti'] ??
                    null,

                'uplink_capacity' =>
                $kcp['uplinkCapacity'] ??
                    null,

                'downlink_capacity' =>
                $kcp['downlinkCapacity'] ??
                    null,

                'congestion' =>
                $kcp['congestion'] ??
                    null,

                'read_buffer_size' =>
                $kcp['readBufferSize'] ??
                    null,

                'write_buffer_size' =>
                $kcp['writeBufferSize'] ??
                    null,

                'header' =>
                $kcp['header'] ??
                    null,

                'seed' =>
                $kcp['seed'] ??
                    null,

                'raw' => $kcp,
            ];
        }

        /*
         * Hysteria transport.
         */
        if (isset($stream['hysteriaSettings'])) {

            $hysteria =
                $stream['hysteriaSettings'];

            $result['transport'] = [
                'type' => 'hysteria',

                'version' =>
                $hysteria['version'] ??
                    null,

                'auth' =>
                $hysteria['auth'] ??
                    null,

                'up' =>
                $hysteria['up'] ??
                    null,

                'down' =>
                $hysteria['down'] ??
                    null,

                'obfs' =>
                $hysteria['obfs'] ??
                    null,

                'raw' => $hysteria,
            ];
        }

        /*
         * Socket options.
         */
        if (isset($stream['sockopt'])) {

            $result['sockopt'] =
                $stream['sockopt'];
        }

        /*
         * Preserve complete streamSettings.
         */
        $result['stream_settings'] =
            $stream;
    }

    /**
     * Direct NPVT profile extraction.
     *
     * Used when v2rayJson is empty.
     */
    protected function extractDirectProfile(
        array $config,
        array $profile,
        string $protocol,
        array &$result
    ): void {

        /*
         * Common endpoint.
         */
        $result['address'] =
            $profile['server'] ??
            $profile['address'] ??
            null;

        $result['port'] =
            $this->normalizePort(
                $profile['serverPort'] ??
                    $profile['port'] ??
                    null
            );

        /*
         * Common credentials.
         */
        $result['uuid'] =
            $profile['uuid'] ??
            $profile['id'] ??
            null;

        $result['password'] =
            $profile['password'] ??
            null;

        $result['username'] =
            $profile['username'] ??
            $profile['user'] ??
            null;

        $result['method'] =
            $profile['method'] ??
            $profile['security'] ??
            $profile['encryptionMethod'] ??
            null;

        $result['encryption'] =
            $profile['encryption'] ??
            null;

        $result['flow'] =
            $profile['flow'] ??
            null;

        $result['network'] =
            $profile['network'] ??
            null;

        /*
         * Security.
         */
        if (!empty($profile['security'])) {
            $security = strtolower(
                (string) $profile['security']
            );

            if (in_array($security, [
                'none',
                'tls',
                'reality',
            ], true)) {
                $result['security'] =
                    $security;
            }
        }

        /*
         * Direct profile transport fields.
         */
        $result['transport'] = [
            'type' =>
            $profile['network'] ??
                null,

            'host' =>
            $profile['host'] ??
                null,

            'path' =>
            $profile['path'] ??
                null,

            'service_name' =>
            $profile['serviceName'] ??
                $profile['service_name'] ??
                null,

            'header_type' =>
            $profile['headerType'] ??
                $profile['header_type'] ??
                null,

            'mode' =>
            $profile['mode'] ??
                null,

            'raw' => [
                'host' =>
                $profile['host'] ??
                    null,

                'path' =>
                $profile['path'] ??
                    null,

                'serviceName' =>
                $profile['serviceName'] ??
                    null,

                'headerType' =>
                $profile['headerType'] ??
                    null,

                'mode' =>
                $profile['mode'] ??
                    null,
            ],
        ];

        /*
         * TLS fields in direct profile.
         */
        if ($result['security'] === 'tls') {

            $result['tls'] = [
                'server_name' =>
                $profile['serverName'] ??
                    $profile['sni'] ??
                    null,

                'alpn' =>
                $this->normalizeAlpn(
                    $profile['alpn'] ?? null
                ),

                'allow_insecure' =>
                $profile['allowInsecure'] ??
                    $profile['insecure'] ??
                    null,

                'fingerprint' =>
                $profile['fingerprint'] ??
                    null,

                'raw' => $profile,
            ];
        }

        /*
         * REALITY fields in direct profile.
         */
        if ($result['security'] === 'reality') {

            $result['reality'] = [
                'server_name' =>
                $profile['serverName'] ??
                    $profile['sni'] ??
                    null,

                'fingerprint' =>
                $profile['fingerprint'] ??
                    null,

                'public_key' =>
                $profile['publicKey'] ??
                    $profile['public_key'] ??
                    null,

                'short_id' =>
                $profile['shortId'] ??
                    $profile['short_id'] ??
                    null,

                'spider_x' =>
                $profile['spiderX'] ??
                    $profile['spider_x'] ??
                    null,

                'raw' => $profile,
            ];
        }
    }

    /**
     * Fill address/port from top-level NPVT fields.
     */
    protected function fillEndpointFallback(
        array $config,
        array $profile,
        array &$result
    ): void {

        if (
            empty($result['address']) &&
            !empty($config['address'])
        ) {

            [
                $host,
                $port
            ] = $this->parseHostPort(
                (string) $config['address']
            );

            $result['address'] =
                $host;

            if (
                $result['port'] === null &&
                $port !== null
            ) {
                $result['port'] =
                    $port;
            }
        }

        if (
            empty($result['address']) &&
            !empty($profile['server'])
        ) {
            $result['address'] =
                $profile['server'];
        }

        if (
            $result['port'] === null &&
            !empty($profile['serverPort'])
        ) {
            $result['port'] =
                $this->normalizePort(
                    $profile['serverPort']
                );
        }
    }

    /**
     * Parse host:port including IPv6.
     */
    protected function parseHostPort(
        string $value
    ): array {

        $value = trim($value);

        /*
         * IPv6 in [addr]:port
         */
        if (
            preg_match(
                '/^\[(.+)]:(\d+)$/',
                $value,
                $m
            )
        ) {
            return [
                $m[1],
                (int) $m[2],
            ];
        }

        /*
         * Normal hostname:port.
         */
        if (
            preg_match(
                '/^(.+):(\d+)$/',
                $value,
                $m
            )
        ) {
            return [
                $m[1],
                (int) $m[2],
            ];
        }

        return [
            $value,
            null,
        ];
    }

    /**
     * Normalize ALPN.
     */
    protected function normalizeAlpn(
        mixed $alpn
    ): ?string {

        if (is_array($alpn)) {
            return implode(',', $alpn);
        }

        if ($alpn === null) {
            return null;
        }

        return (string) $alpn;
    }

    /**
     * Normalize port.
     */
    protected function normalizePort(
        mixed $port
    ): ?int {

        if (
            $port === null ||
            $port === ''
        ) {
            return null;
        }

        if (is_numeric($port)) {
            return (int) $port;
        }

        return null;
    }

    /**
     * UUID detector.
     */
    protected function looksLikeUuid(
        string $value
    ): bool {

        return (bool) preg_match(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i',
            trim($value)
        );
    }
}
