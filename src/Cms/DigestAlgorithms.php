<?php

declare(strict_types=1);

namespace PurePhpCms\Cms;

use PurePhpCms\Exception\CmsException;

/** 将 CMS 摘要 OID、PHP hash 名称和 OpenSSL 常量集中管理。 */
final class DigestAlgorithms
{
    public static function byName($name)
    {
        switch (strtolower($name)) {
            case 'sha1':
                return ['name' => 'sha1', 'oid' => ObjectIdentifiers::SHA1, 'openssl' => OPENSSL_ALGO_SHA1];
            case 'sha256':
                return ['name' => 'sha256', 'oid' => ObjectIdentifiers::SHA256, 'openssl' => OPENSSL_ALGO_SHA256];
            default:
                throw new CmsException('不支持的摘要算法：' . $name);
        }
    }

    public static function byOid($oid)
    {
        if ($oid === ObjectIdentifiers::SHA1) {
            return self::byName('sha1');
        }
        if ($oid === ObjectIdentifiers::SHA256) {
            return self::byName('sha256');
        }
        throw new CmsException('不支持的摘要算法 OID：' . $oid);
    }
}
