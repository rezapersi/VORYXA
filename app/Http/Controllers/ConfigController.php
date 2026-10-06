<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Services\Config\ConfigService;

class ConfigController extends Controller
{


    public function __construct(
        protected ConfigService $configservice
    ) {}

    public  function getconfigs()
    {
        $get = $this->configservice->GetConfigs();
        return response()->json([
            'success' => true,
            'data' => $get,
        ], 200);
    }
}
