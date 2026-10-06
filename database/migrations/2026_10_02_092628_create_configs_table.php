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
        Schema::create('configs', function (Blueprint $table) {
            $table->id();
            $table->string('name', 255)->nullable();
            $table->string('ip', 255)->nullable();
            $table->string('country_name')->nullable();
            $table->string('country_code')->nullable();
            $table->string('type')->default('free');
            $table->string('protocol')->nullable();
            $table->text('uri')->nullable();
            $table->string('tel_channel_id')->nullable();
            $table->string('filename', 255)->nullable();
            $table->integer('serverid')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('configs');
    }
};
