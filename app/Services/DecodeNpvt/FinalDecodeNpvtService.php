<?php

namespace App\Services\DecodeNpvt;


use App\Services\DecodeNpvt\DecodeNpvt;
use App\Services\DecodeNpvt\NpvtExport;
use App\Services\DecodeNpvt\ConnectionProfile;
use App\Services\DecodeNpvt\ConnectionUriBuilder;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\File;
use Stevebauman\Location\Facades\Location;
use App\Models\Config;




class FinalDecodeNpvtService
{


    public function __construct(
        protected DecodeNpvt $decodenpvt,
        protected NpvtExport $npvtexport,
        protected ConnectionProfile $connectionprofile,
        protected ConnectionUriBuilder $uribuilder,
    ) {}


    public function decode($BeforeFileName, $NewFileName, $ChannelId)
    {

        if ($BeforeFileName) {
            $PathBeforeFile =  storage_path('app/telegram/downloads/' . $BeforeFileName);
            if (file_exists($PathBeforeFile)) {
                // remove before File
                File::delete($PathBeforeFile);
            }
        }

        // Delete Before Config
        Config::where('tel_channel_id', $ChannelId)->delete();
        $PathNewFile = storage_path('app/telegram/downloads/' . $NewFileName);
        if (file_exists($PathNewFile)) {
            $contents = file_get_contents($PathNewFile);
            $decoded = $this->decodenpvt->decodeNpvt($contents);
            $configs = $this->npvtexport->export($decoded);
            foreach ($configs as $config) {
                try {
                    $normalized = $this->connectionprofile->normalize($config);
                    $uri = $this->uribuilder->build($normalized);
                    $ip = $config['address'];
                    $location = Location::get($ip);


                    $nameConfig;
                    for ($i = 1; $i <= 5; $i++) {
                        $nameConfig = $location->countryName . ' - ' . rand(1, 30);
                        $check = Config::where('name', $nameConfig)->first();
                        if (!$check) {
                            $i = 5;
                        }
                    }

                    Config::create([
                        'name' => $nameConfig,
                        'beforename' => $config['name'],
                        'ip' =>  $ip,
                        'country_name' => $location->countryName,
                        'country_code' => $location->countryCode,
                        'type' => 'free',
                        'protocol' =>  $config['protocol'],
                        'uri' => $uri,
                        'tel_channel_id' => $ChannelId,
                        'filename' => $NewFileName,
                    ]);
                } catch (\Throwable $e) {

                    dump([
                        'name' => $config['name'] ?? null,
                        'protocol' => $config['protocol'] ?? null,
                        'error' => $e->getMessage(),
                    ]);
                }
            }




            //end

        }
    }
}
