<?php

declare(strict_types=1);

namespace PurePhpCms\Crypto;

/** ANSI X9.63 KDF，CMS ECDH 使用 SHA-256 派生 key-encryption key。 */
final class X963Kdf
{
    public static function derive($sharedSecret, $sharedInfo, $length)
    {
        $result = '';
        for ($counter = 1; strlen($result) < $length; $counter++) {
            $result .= hash(
                'sha256',
                $sharedSecret . pack('N', $counter) . $sharedInfo,
                true
            );
        }
        return substr($result, 0, $length);
    }
}
