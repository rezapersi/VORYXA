<?php

namespace App\Services\Setting;

use App\Http\Resources\SettingResource;
use App\Models\Setting;



class SettingService
{

    public function GetSettings()
    {
        return SettingResource::collection(Setting::all());
    }
}
