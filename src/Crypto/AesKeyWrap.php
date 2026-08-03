<?php

declare(strict_types=1);

namespace PurePhpCms\Crypto;

use PurePhpCms\Exception\CmsException;

/** RFC 3394 AES Key Wrap，用于 KEKRecipientInfo 的密钥封装。 */
final class AesKeyWrap
{
    const INITIAL_VALUE = "\xA6\xA6\xA6\xA6\xA6\xA6\xA6\xA6";

    public static function wrap($keyEncryptionKey, $plaintextKey)
    {
        self::validate($keyEncryptionKey, $plaintextKey);
        $blocks = str_split($plaintextKey, 8);
        $register = self::INITIAL_VALUE;
        $count = count($blocks);

        for ($round = 0; $round < 6; $round++) {
            for ($index = 1; $index <= $count; $index++) {
                $encrypted = self::encryptBlock(
                    $keyEncryptionKey,
                    $register . $blocks[$index - 1]
                );
                $counter = $count * $round + $index;
                $register = self::xorCounter(substr($encrypted, 0, 8), $counter);
                $blocks[$index - 1] = substr($encrypted, 8, 8);
            }
        }
        return $register . implode('', $blocks);
    }

    public static function unwrap($keyEncryptionKey, $wrappedKey)
    {
        self::validate($keyEncryptionKey, substr($wrappedKey, 8));
        if (strlen($wrappedKey) < 24 || strlen($wrappedKey) % 8 !== 0) {
            throw new CmsException('AES Key Wrap 密文长度无效');
        }

        $register = substr($wrappedKey, 0, 8);
        $blocks = str_split(substr($wrappedKey, 8), 8);
        $count = count($blocks);

        for ($round = 5; $round >= 0; $round--) {
            for ($index = $count; $index >= 1; $index--) {
                $counter = $count * $round + $index;
                $decrypted = self::decryptBlock(
                    $keyEncryptionKey,
                    self::xorCounter($register, $counter) . $blocks[$index - 1]
                );
                $register = substr($decrypted, 0, 8);
                $blocks[$index - 1] = substr($decrypted, 8, 8);
            }
        }

        if (!hash_equals(self::INITIAL_VALUE, $register)) {
            throw new CmsException('AES Key Wrap 完整性检查失败');
        }
        return implode('', $blocks);
    }

    private static function validate($keyEncryptionKey, $plaintextKey)
    {
        if (!in_array(strlen($keyEncryptionKey), [16, 24, 32], true)) {
            throw new CmsException('AES KEK 必须为 16、24 或 32 字节');
        }
        if (strlen($plaintextKey) < 16 || strlen($plaintextKey) % 8 !== 0) {
            throw new CmsException('被封装密钥必须至少 16 字节且为 8 的倍数');
        }
    }

    private static function cipher($key)
    {
        return 'aes-' . (strlen($key) * 8) . '-ecb';
    }

    private static function encryptBlock($key, $block)
    {
        $result = openssl_encrypt(
            $block,
            self::cipher($key),
            $key,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING
        );
        if ($result === false) throw new CmsException('AES Key Wrap 加密失败');
        return $result;
    }

    private static function decryptBlock($key, $block)
    {
        $result = openssl_decrypt(
            $block,
            self::cipher($key),
            $key,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING
        );
        if ($result === false) throw new CmsException('AES Key Wrap 解密失败');
        return $result;
    }

    private static function xorCounter($register, $counter)
    {
        // t 在实际 CMS 消息规模内小于 2^32，高 32 位保持为零。
        return $register ^ pack('N2', 0, $counter);
    }
}
