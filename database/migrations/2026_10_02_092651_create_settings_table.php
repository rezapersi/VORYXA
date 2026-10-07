<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('settings', function (Blueprint $table) {
            $table->id();
            $table->integer('timeconnection')->default(60); // برحسب دقیقه
            $table->boolean('activeads')->default(1);
            $table->boolean('rewardpart')->default(1);
            $table->string('website')->nullable();
            $table->string('contact')->nullable();
            $table->text('rateapplink')->nullable();
            $table->string('adslevelmain', 255)->nullable();
            $table->string('adslevelreward', 255)->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('settings');
    }
};
