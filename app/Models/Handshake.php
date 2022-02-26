<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;

class Handshake extends Model
{
    use HasFactory;

    protected $fillable = ['shared_key', 'expires_at'];

    protected $dates = ['expires_at'];

    protected static function boot()
    {
        parent::boot();

        static::creating(function ($handshake) {
            $handshake->{$handshake->getKeyName()} = (string) Str::uuid();
        });
    }

    public function getIncrementing(): bool
    {
        return false;
    }

    public function getKeyType(): string
    {
        return 'string';
    }
}
