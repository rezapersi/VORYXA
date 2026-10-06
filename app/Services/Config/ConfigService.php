<?php

namespace App\Services\Config;

use App\Http\Resources\ConfigResource;
use App\Models\Config;



class ConfigService
{

    public function GetConfigs()
    {
        return ConfigResource::collection(Config::all());
    }
}
