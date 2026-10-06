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
        Schema::create('telchanels', function (Blueprint $table) {
            $table->id();
            $table->timestamps();
            $table->string('username')->unique()->nullable(); // مثل @channel_name
            $table->string('title')->nullable(); // نام نمایشی کانال
            $table->string('last_name_file', 255)->nullable();
            $table->unsignedBigInteger('last_message_id')->default(0); // آخرین پیام پردازش شده
            $table->boolean('is_active')->default(true); // فعال/غیرفعال برای اسکن
            $table->timestamp('last_checked_at')->nullable(); // آخرین زمان بررسی
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('telchanels');
    }
};
