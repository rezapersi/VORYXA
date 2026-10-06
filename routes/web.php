<?php

use Illuminate\Support\Facades\Route;
use Inertia\Inertia;
use App\Http\Controllers\DecodeNpvtController;
use App\Http\Controllers\TelegramController;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\File;
use Stevebauman\Location\Facades\Location;





use App\Http\Resources\ConfigResource;
use App\Models\Config;






use App\Models\Telchanel;



Route::get('/', function () {
    return Inertia::render('Welcome');
})->name('home');



Route::get('/test', function () {


    $ip = '199.232.239.239';
    $location = Location::get($ip);
    
    dd($location);

   
});

 
Route::get('/getconfig', function () {
  return ConfigResource::collection(Config::all());
});


// Decode Npvt

Route::get('/decode', [DecodeNpvtController::class, 'index']);

// Get Npvt From Telegram

Route::get('/getnpvt', [TelegramController::class, 'getnpvt']);




Route::get('insertchannel', function () {

    Telchanel::create([
        'username' => '@V2rayEnglish',
        'title' => 'سرور - کانفیگ رایگان',
        'last_message_id' => 0
    ]);

    dd('ok');
});







Route::get('dashboard', function () {
    return Inertia::render('Dashboard');
})->middleware(['auth', 'verified'])->name('dashboard');

require __DIR__ . '/settings.php';
require __DIR__ . '/auth.php';
