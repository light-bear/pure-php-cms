<?php

declare(strict_types=1);

namespace PurePhpCms\Cms;

/** RFC 3852 定义的六种标准 CMS 内容类型。 */
final class ContentTypes
{
    const DATA = '1.2.840.113549.1.7.1';
    const SIGNED_DATA = '1.2.840.113549.1.7.2';
    const ENVELOPED_DATA = '1.2.840.113549.1.7.3';
    const DIGESTED_DATA = '1.2.840.113549.1.7.5';
    const ENCRYPTED_DATA = '1.2.840.113549.1.7.6';
    const AUTHENTICATED_DATA = '1.2.840.113549.1.9.16.1.2';

    private static $names = [
        self::DATA => 'data',
        self::SIGNED_DATA => 'signedData',
        self::ENVELOPED_DATA => 'envelopedData',
        self::DIGESTED_DATA => 'digestedData',
        self::ENCRYPTED_DATA => 'encryptedData',
        self::AUTHENTICATED_DATA => 'authenticatedData',
    ];

    public static function name($oid)
    {
        return isset(self::$names[$oid]) ? self::$names[$oid] : 'unknown';
    }

    public static function isStandard($oid)
    {
        return isset(self::$names[$oid]);
    }
}
