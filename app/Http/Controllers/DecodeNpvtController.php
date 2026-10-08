<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

use App\Services\DecodeNpvt\DecodeNpvt;
use App\Services\DecodeNpvt\NpvtExport;
use App\Services\DecodeNpvt\ConnectionProfile;
use App\Services\DecodeNpvt\ConnectionUriBuilder;

class DecodeNpvtController extends Controller
{


    public function __construct(
        protected DecodeNpvt $decodenpvt,
        protected NpvtExport $npvtexport,
        protected ConnectionProfile $connectionprofile,
        protected ConnectionUriBuilder $uribuilder,
    ) {}

    public function index(Request $request)
    {

        //1791230356_14031.npvt

        $path = public_path('npvt/test.npvt');
        if (file_exists($path)) {
            $contents = file_get_contents($path);
            $decoded = $this->decodenpvt->decodeNpvt($contents);
            $configs = $this->npvtexport->export($decoded);



            //  return response()->json([
            //     'count' => count($configs),
            //     'configs' => $configs,
            // ]);


            //  $normalized = $this->connectionprofile->normalize($configs);
            //   dd($normalized['normalized']);


            // $uri = $this->uribuilder->build($normalized);
            // dd($normalized['all'], $uri);


            //   $profile = $this->connectionprofile->normalize($configs[22]);
            //     return response()->json(['configs' => $profile,
            //   ]);


            // $url = $this->uribuilder->build($profile);
            // dd($configs[22],$profile,$url);


            // Test builder uri



            // foreach ($configs as $config) {


            //     if (
            //         str_contains(
            //             (string) ($config['name'] ?? ''),
            //             '🎃9'
            //         )
            //     ) {
            //         // dump([
            //         //     'name' => $config['name'] ?? null,
            //         //     'protocol' => $config['protocol'] ?? null,
            //         //     'address' => $config['address'] ?? null,
            //         //     'port' => $config['port'] ?? null,
            //         //     'method' => $config['method'] ?? null,
            //         //     'password' => $config['password'] ?? null,
            //         //     'network' => $config['network'] ?? null,
            //         //     'security' => $config['security'] ?? null,
            //         //     'host' => $config['host'] ?? null,
            //         //     'path' => $config['path'] ?? null,
            //         //     'sni' => $config['sni'] ?? null,
            //         //     'alpn' => $config['alpn'] ?? null,
            //         //     'fingerPrint' => $config['fingerPrint'] ?? null,
            //         //     'insecure' => $config['insecure'] ?? null,
            //         // ]);

            //         $normalized = $this->connectionprofile->normalize($config);

            //         $url = $this->uribuilder->build($normalized);

            //         dd($url);

            //         dump([
            //             'name'       => $config['name'] ?? null,
            //             'protocol'   => $config['protocol'] ?? null,
            //             'address'    => $config['address'] ?? null,
            //             'port'       => $config['port'] ?? null,
            //             'method'     => $config['method'] ?? null,
            //             'password'   => $config['password'] ?? null,
            //             'network'    => $config['network'] ?? null,
            //             'security'   => $config['security'] ?? null,

            //             'transport'  => $config['transport'] ?? null,

            //             'tls'        => $config['tls'] ?? null,

            //             'raw_profile' => $config['raw_profile'] ?? null,
            //         ]);
            //     }
            // }


            foreach ($configs as $config) {

                try {
                    $normalized = $this->connectionprofile->normalize($config);
                    $url = $this->uribuilder->build($normalized);
                    dump([
                        'name' => $config['name'] ?? null,
                        'protocol' => $config['protocol'] ?? null,
                        'url' => $url,
                        'config' => $config,
                    ]);
                } catch (\Throwable $e) {

                    dump([
                        'name' => $config['name'] ?? null,
                        'protocol' => $config['protocol'] ?? null,
                        'error' => $e->getMessage(),
                    ]);
                }
            }
        }




        //end


    }
}
