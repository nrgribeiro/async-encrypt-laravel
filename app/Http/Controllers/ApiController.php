<?php

namespace App\Http\Controllers;

use App\Models\Handshake;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

class ApiController extends Controller
{
    //
    public function handshake(Request $request): \Illuminate\Http\JsonResponse
    {
        // Get public generated in frontend client
        $publicKey = $request->get('publicKey');

        // generate a random string to be used as shared key
        $data = Str::random(32);

        // encrypt the shared key using the client's public key
        // so only the client's matching private key can decrypt
        openssl_public_encrypt($data,$encrypted_data, $publicKey, OPENSSL_PKCS1_PADDING);

        // save the shared key temporarily
        $handshake = Handshake::create(
            [
                'shared_key' => $data,
                'expires_at' => Carbon::now()->addMinutes(5),
            ]
        );

        // return the encrypted shared key and the handshake id
        return response()->json([
            'encryptedKey' => base64_encode($encrypted_data),
            'handshakeId' => $handshake->id,
        ]);
    }

    public function updateAccount(Request $request)
    {
        // get the handshake id
        $handshakeId = $request->get('handshakeId');

        // check if handshake exists and is still valid
        $validHandshake = Handshake::whereId($handshakeId)
            ->whereRaw(
                "expires_at > STR_TO_DATE(?, '%Y-%m-%d %H:%i:%s')",
                Carbon::now()->format('Y-m-d H:i:s')
            )
            ->first();

        if(!$validHandshake)
            return response()->json(['error' => 'invalid handshake'], 422);

        // get the encrypted data from client and base 64 decode it
        $encryptedMsg = base64_decode($request->get('encryptedData'));

        // get the first 16 bytes from the payload (must match the IV byte length)
        $iv = mb_substr($encryptedMsg,0, 16, '8bit');

        // get the encrypted value part (should match the rest of the payload)
        $encrypted = mb_substr($encryptedMsg, 16, null, '8bit');

        // decrypt the value
        $decryptedData = openssl_decrypt(
            $encrypted,
            'aes-256-cbc',
            $validHandshake->shared_key,
            OPENSSL_RAW_DATA,
            $iv
        );

        return response()->json(['message' => 'success']);
    }
}
