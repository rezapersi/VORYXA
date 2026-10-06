<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Telchanel extends Model
{

    protected $fillable = [
        'username',
        'title',
        'last_message_id',
        'is_active',
        'last_checked_at',
        'last_name_file',
    ];
}
