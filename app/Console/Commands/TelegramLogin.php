<?php

namespace App\Console\Commands;

use App\Services\Telegram\TelegramService;
use Illuminate\Console\Command;

class TelegramLogin extends Command
{
    protected $signature = 'telegram:login';
    protected $description = 'ورود به اکانت تلگرام و ساخت سشن';

    public function handle(TelegramService $telegram): int
    {
        $this->info('🚀 در حال شروع فرآیند ورود...');
        $this->warn('⚠️  لطفاً شماره تلفن، کد تأیید و در صورت نیاز رمز دو مرحله‌ای را وارد کنید.');
        $this->newLine();

        try {
            $telegram->login();
            $this->newLine();
            $this->info('✅ ورود با موفقیت انجام شد. سشن ذخیره شد.');
            return Command::SUCCESS;
        } catch (\Throwable $e) {
            $this->error('❌ خطا در ورود: ' . $e->getMessage());
            return Command::FAILURE;
        }
    }
}
