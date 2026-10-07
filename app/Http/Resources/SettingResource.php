<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class SettingResource extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'timeconnection' => $this->timeconnection,
            'activeads' => $this->activeads,
            'rewardpart' => $this->rewardpart,
            'website' => $this->website,
            'contact' => $this->contact,
            'rateapplink' => $this->rateapplink,
            'adslevelmain' => $this->adslevelmain,
            'adslevelreward' => $this->adslevelreward,
        ];
    }
}
