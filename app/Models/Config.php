<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Config extends Model
{
   
    protected $fillable = [
        'name' ,
        'beforename' ,
        'ip' ,
        'country_name' ,
        'country_code' ,
        'type' ,
        'protocol' ,
        'uri' ,
        'tel_channel_id' ,
        'filename' ,
        
    ];



}
