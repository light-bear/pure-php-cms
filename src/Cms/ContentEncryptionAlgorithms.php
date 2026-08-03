<?php

declare(strict_types=1);

namespace PurePhpCms\Cms;

use PurePhpCms\Exception\CmsException;

/** CMS 内容加密算法注册表。 */
final class ContentEncryptionAlgorithms
{
    const AES_128_CBC_OID = '2.16.840.1.101.3.4.1.2';
    const AES_256_CBC_OID = '2.16.840.1.101.3.4.1.42';

    public static function byName($name)
    {
        switch (strtolower($name)) {
            case 'aes-128-cbc':
                return [
                    'name' => 'aes-128-cbc',
                    'oid' => self::AES_128_CBC_OID,
                    'keyLength' => 16,
                    'ivLength' => 16,
                ];
            case 'aes-256-cbc':
                return [
                    'name' => 'aes-256-cbc',
                    'oid' => self::AES_256_CBC_OID,
                    'keyLength' => 32,
                    'ivLength' => 16,
                ];
            default:
                throw new CmsException('不支持的内容加密算法：' . $name);
        }
    }

    public static function byOid($oid)
    {
        if ($oid === self::AES_128_CBC_OID) {
            return self::byName('aes-128-cbc');
        }
        if ($oid === self::AES_256_CBC_OID) {
            return self::byName('aes-256-cbc');
        }
        throw new CmsException('不支持的内容加密算法 OID：' . $oid);
    }

    public static function assertKeyLength($key, array $algorithm)
    {
        if (strlen($key) !== $algorithm['keyLength']) {
            throw new CmsException(sprintf(
                '%s 密钥必须为 %d 字节',
                $algorithm['name'],
                $algorithm['keyLength']
            ));
        }
    }
}
