<?php

namespace App\Console\Commands;

use App\Models\Telchanel;
use App\Services\Telegram\TelegramService;
use App\Services\DecodeNpvt\FinalDecodeNpvtService;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Cache;

class ScanTelchanels extends Command
{
    protected $signature = 'telegram:scan-channels
                            {--channel= : نام کاربری یا لینک کانال خاص}';

    protected $description = 'اسکن کانال‌های تلگرام و دانلود آخرین فایل npvt جدید';

    // ✅ تزریق هر دو سرویس در handle
    public function handle(
        TelegramService $telegram,
        FinalDecodeNpvtService $decodenpvt
    ): int {
        // 🔒 قفل برای جلوگیری از اجرای همزمان
        $lock = Cache::lock('telegram-scan-lock', 900);

        if (!$lock->get()) {
            $this->warn('⏭️  اسکن قبلی هنوز در حال اجراست. رد می‌شود.');
            return Command::SUCCESS;
        }

        try {
            $this->runScan($telegram, $decodenpvt);
        } finally {
            $lock->release();
        }

        return Command::SUCCESS;
    }

    protected function runScan(
        TelegramService $telegram,
        FinalDecodeNpvtService $decodenpvt
    ): void {
        $channelInput = $this->option('channel');

        $channels = $channelInput
            ? Telchanel::where('username', $channelInput)->get()
            : Telchanel::where('is_active', true)->get();

        if ($channels->isEmpty()) {
            $this->error('❌ هیچ کانال فعالی یافت نشد');
            return;
        }

        $this->info("🔍 شروع اسکن " . $channels->count() . " کانال...");
        $this->newLine();

        foreach ($channels as $channel) {
            $this->scanChannel($telegram, $decodenpvt, $channel);
            $this->newLine();
        }

        $this->info("✅ اسکن کامل شد");
    }

    protected function scanChannel(
        TelegramService $telegram,
        FinalDecodeNpvtService $decodenpvt,
        Telchanel $channel
    ): void {
        $this->info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        $this->info("📡 کانال: {$channel->username} ({$channel->title})");

        $isFirstRun = $channel->last_message_id == 0;

        try {
            // 🔑 تبدیل ورودی (لینک یا username) به peer قابل استفاده
            $this->line("   🔄 تبدیل شناسه کانال...");
            $peer = $telegram->resolvePeer($channel->username);
            $this->line("   ✅ Peer: {$peer}");

            // اگر عنوان کانال خالی است، به‌طور خودکار پر کن
            if (empty($channel->title)) {
                $title = $telegram->resolveChannelTitle($channel->username);
                if ($title) {
                    $channel->update(['title' => $title]);
                }
            }

            $limit = $isFirstRun ? 20 : 100;
            $minId = $isFirstRun ? 0 : $channel->last_message_id;

            $this->line($isFirstRun
                ? "   🆕 اولین اجرا"
                : "   📨 بررسی پیام‌های جدیدتر از ID: {$channel->last_message_id}");

            // دریافت پیام‌ها با peer
            $messages = $telegram->getChannelMessagesByPeer($peer, $minId, $limit);

            if (empty($messages)) {
                $this->line("   ⏭️  پیام جدیدی یافت نشد");
                $channel->update(['last_checked_at' => now()]);
                return;
            }

            if (!$isFirstRun) {
                $messages = array_filter($messages, function ($msg) use ($channel) {
                    return ($msg['id'] ?? 0) > $channel->last_message_id;
                });
            }

            $this->line("   📨 " . count($messages) . " پیام جدید");

            if (empty($messages)) {
                $channel->update(['last_checked_at' => now()]);
                return;
            }

            $latestFile = $telegram->findLatestFile($messages, 'npvt');

            if (!$latestFile) {
                $this->line("   ℹ️  فایل npvt جدیدی یافت نشد");

                $maxId = max(array_map(fn($m) => $m['id'] ?? 0, $messages));
                $channel->update([
                    'last_message_id' => $maxId,
                    'last_checked_at' => now(),
                ]);
                return;
            }

            $this->info("   🎯 آخرین فایل npvt پیدا شد:");
            $this->line("      📎 نام: {$latestFile['file_name']}");
            $this->line("      🆔 message_id: {$latestFile['message_id']}");
            $this->line("      📦 حجم: {$latestFile['file_size']} بایت");

            $channel->update([
                'last_message_id' => $latestFile['message_id'],
                'last_checked_at' => now(),
            ]);

            $this->line("   ✅ last_message_id = {$latestFile['message_id']}");

            // ✅ پاس دادن $decodenpvt به handleNewFile
            $this->handleNewFile($telegram, $decodenpvt, $channel, $latestFile);
        } catch (\Throwable $e) {
            $this->error("   ❌ خطا: " . $e->getMessage());
            logger()->error("خطا در اسکن کانال {$channel->username}: " . $e->getMessage());
        }
    }

    protected function handleNewFile(
        TelegramService $telegram,
        FinalDecodeNpvtService $decodenpvt,
        Telchanel $channel,
        array $fileInfo
    ): void {
        $BeforeFileName = $channel->last_name_file;
        $ChannelId = $channel->id;

        $saveDir = storage_path('app/telegram/downloads');
        if (!is_dir($saveDir)) {
            mkdir($saveDir, 0755, true);
        }

        $newFileName = time() . '_' . $fileInfo['message_id'] . '.npvt';
        $savePath = $saveDir . DIRECTORY_SEPARATOR . $newFileName;

        // جلوگیری از تداخل نام
        $counter = 1;
        while (file_exists($savePath)) {
            $newFileName = time() . '_' . $fileInfo['message_id'] . '_' . $counter . '.npvt';
            $savePath = $saveDir . DIRECTORY_SEPARATOR . $newFileName;
            $counter++;
        }

        try {
            $telegram->getClient()->downloadToFile($fileInfo['message'], $savePath);
            $this->info("   💾 فایل دانلود شد: {$newFileName}");

            $channel->update(['last_name_file' => $newFileName]);
            $this->line("   📝 نام فایل در DB ذخیره شد");

            // ✅ فراخوانی Decode
            $decodenpvt->decode($BeforeFileName, $newFileName, $ChannelId);
        } catch (\Throwable $e) {
            $this->error("   ❌ خطا در دانلود: " . $e->getMessage());
            logger()->error("خطا در دانلود {$newFileName}: " . $e->getMessage());
        }
    }
}
