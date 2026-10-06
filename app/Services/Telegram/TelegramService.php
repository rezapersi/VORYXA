<?php

namespace App\Services\Telegram;

use danog\MadelineProto\API;
use danog\MadelineProto\Settings;
use danog\MadelineProto\Settings\AppInfo;
use danog\MadelineProto\Settings\Logger as LoggerSettings; // ✅ کلاس تنظیمات لاگ
use danog\MadelineProto\Settings\Connection;
use danog\MadelineProto\Settings\Files;
use danog\MadelineProto\Logger; // ✅ کلاس اصلی برای ثابت‌ها

class TelegramService
{
    protected API $client;


    public function __construct()
    {
        $sessionPath = storage_path('app/telegram/session.madeline');

        $settings = new Settings;

        // تنظیمات API
        // $settings->setAppInfo(
        //     (new AppInfo)
        //         ->setApiId((int) env('TELEGRAM_API_ID'))
        //         ->setApiHash(env('TELEGRAM_API_HASH'))
        // );

        $settings->setAppInfo(
            (new AppInfo)
                ->setApiId((int) config('telegram.api_id'))
                ->setApiHash(config('telegram.api_hash'))
        );

        // لاگ
        $settings->setLogger(
            (new LoggerSettings)->setLevel(Logger::LEVEL_ERROR)
        );

        // ✅ تنظیمات اتصال (اصلاح‌شده برای رفع خطای دانلود)
        $settings->setConnection(
            (new Connection)
                ->setTimeout(60)                  // افزایش تایم‌اوت به ۶۰ ثانیه
                ->setMaxMediaSocketCount(5)       // افزایش تعداد سوکت‌های مدیا
        );

        // ✅ تنظیمات فایل (اصلاح‌شده - متد صحیح)
        $settings->setFiles(
            (new Files)
                ->setDownloadParallelChunks(10) // ✅ تعداد چانک‌های موازی برای دانلود
        );

        $this->client = new API($sessionPath, $settings);
    }


    public function getClient(): API
    {
        return $this->client;
    }

    public function login(): void
    {
        $this->client->start();
    }


    /**
     * دریافت پیام‌های کانال از یک ID مشخص به بعد
     *
     * @param string $channelUsername نام کاربری کانال (مثلاً @my_channel)
     * @param int $minId آخرین ID پیام دانلود شده (0 برای شروع از ابتدا)
     * @param int $limit حداکثر تعداد پیام
     * @return array
     */
    /**
     * دریافت پیام‌های کانال از یک ID مشخص به بعد
     */
    public function getChannelMessages(string $channelUsername, int $minId = 0, int $limit = 100): array
    {
        $client = $this->getClient();

        try {
            // MadelineProto خودش username را به peer تبدیل می‌کند
            $result = $client->messages->getHistory(
                peer: $channelUsername,
                offset_id: 0,
                offset_date: 0,
                add_offset: 0,
                limit: $limit,
                max_id: 0,
                min_id: $minId,
                hash: 0
            );

            // تبدیل خروجی به آرایه (چون MadelineProto 8 آبجکت برمی‌گرداند)
            $result = json_decode(json_encode($result), true);

            return $result['messages'] ?? [];
        } catch (\Throwable $e) {
            logger()->error("خطا در دریافت پیام‌های {$channelUsername}: " . $e->getMessage());
            return [];
        }
    }


    /**
     * پیدا کردن آخرین فایل npvt از میان پیام‌ها
     * فقط آخرین فایل (بزرگ‌ترین message_id) را برمی‌گرداند
     *
     * @param array $messages آرایه پیام‌ها
     * @param string $extension پسوند مورد نظر (پیش‌فرض: npvt)
     * @return array|null اطلاعات فایل یا null اگر پیدا نشد
     */
    public function findLatestFile(array $messages, string $extension = 'npvt'): ?array
    {
        // مرتب‌سازی نزولی بر اساس message_id (جدیدترین اول)
        usort($messages, fn($a, $b) => ($b['id'] ?? 0) <=> ($a['id'] ?? 0));

        foreach ($messages as $message) {
            if (!isset($message['media']['document'])) {
                continue;
            }

            $document = $message['media']['document'];
            $fileName = null;

            foreach ($document['attributes'] ?? [] as $attr) {
                if (isset($attr['file_name'])) {
                    $fileName = $attr['file_name'];
                    break;
                }
            }

            if (!$fileName) {
                continue;
            }

            $ext = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
            if ($ext !== strtolower($extension)) {
                continue;
            }

            // ✅ پیدا شد! فقط همین یکی را برمی‌گردان
            return [
                'message_id' => $message['id'],
                'file_name' => $fileName,
                'file_size' => $document['size'] ?? 0,
                'message' => $message, // پیام کامل برای دانلود در صورت نیاز
            ];
        }

        return null;
    }


    /**
     * تشخیص نوع ورودی و تبدیل آن به peer قابل استفاده در getHistory
     * 
     * @param string $input می‌تواند username (@channel) یا لینک دعوت (https://t.me/+...) باشد
     * @return string|int شناسه peer
     */
    public function resolvePeer(string $input): string|int
    {
        // اگر لینک دعوت است
        if (str_starts_with($input, 'https://t.me/+') || str_starts_with($input, 't.me/+')) {
            try {
                $info = $this->getClient()->getInfo($input);

                // در MadelineProto 8، bot_api_id معمولاً با -100 شروع می‌شود
                $channelId = $info['bot_api_id'] ?? null;

                if (!$channelId) {
                    throw new \Exception("شناسه کانال از لینک استخراج نشد");
                }

                // اگر از قبل با -100 شروع می‌شود، همان را برگردان
                // در غیر این صورت، پیشوند -100 را اضافه کن
                if (str_starts_with((string) $channelId, '-100')) {
                    return (string) $channelId;
                }

                return '-100' . $channelId;
            } catch (\Throwable $e) {
                logger()->error("خطا در استخراج شناسه از {$input}: " . $e->getMessage());
                throw $e;
            }
        }

        return $input;
    }

    /**
     * دریافت نام نمایشی کانال (برای ذخیره در دیتابیس)
     */
    public function resolveChannelTitle(string $input): ?string
    {
        try {
            $info = $this->getClient()->getInfo($input);
            return $info['Chat']['title'] ?? null;
        } catch (\Throwable $e) {
            return null;
        }
    }



    /**
     * دریافت پیام‌ها با استفاده از peer (username یا شناسه عددی)
     */
    public function getChannelMessagesByPeer(string|int $peer, int $minId = 0, int $limit = 100): array
    {
        try {
            $result = $this->getClient()->messages->getHistory(
                peer: $peer,
                offset_id: 0,
                offset_date: 0,
                add_offset: 0,
                limit: $limit,
                max_id: 0,
                min_id: $minId,
                hash: 0
            );

            $result = json_decode(json_encode($result), true);
            return $result['messages'] ?? [];
        } catch (\Throwable $e) {
            logger()->error("خطا در دریافت پیام‌های {$peer}: " . $e->getMessage());
            return [];
        }
    }
}
