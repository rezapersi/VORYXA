<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Services\Setting\SettingService;

class SettingController extends Controller
{


    public function __construct(
        protected SettingService $settingservice
    ) {}

    public  function getconfigs()
    {
        $get = $this->settingservice->GetSettings();
        return response()->json([
            'success' => true,
            'data' => $get,
        ], 200);
    }
}
