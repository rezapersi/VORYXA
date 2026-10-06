<?php

use Illuminate\Foundation\Inspiring;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Schedule;

// Artisan::command('inspire', function () {
//     $this->comment(Inspiring::quote());
// })->purpose('Display an inspiring quote');


Schedule::command('telegram:scan-channels')
    ->everyFifteenMinutes()
    ->withoutOverlapping(20)  // اگر اجرای قبلی طول کشید، اجرای بعدی رد شود
    ->appendOutputTo(storage_path('logs/telegram-scan.log'));



    