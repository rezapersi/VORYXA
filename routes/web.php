<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Artisan;
use Inertia\Inertia;
use App\Models\Telchanel;



Route::get('insertchannel', function () {

    Telchanel::create([
        'username' => '@V2rayEnglish',
        'title' => 'سرور - کانفیگ رایگان',
        'last_message_id' => 0
    ]);

    dd('ok');
});



Route::get('/removecache', function () {
    $exitCode = Artisan::call('cache:clear');
    $exitCode = Artisan::call('config:clear');
    $exitCode = Artisan::call('config:cache');

    return 'DONE'; //Return anything
});

Route::get('dashboard', function () {
    return Inertia::render('Dashboard');
})->middleware(['auth', 'verified'])->name('dashboard');

require __DIR__ . '/settings.php';
require __DIR__ . '/auth.php';
