<?php

declare(strict_types=1);

namespace PurePhpCms\Tests;

use OpenSSLAsymmetricKey;
use PHPUnit\Framework\TestCase;
use PurePhpCms\Asn1\Decoder;
use PurePhpCms\Asn1\Encoder;
use PurePhpCms\Cms\ContentInfo;

abstract class CmsTestCase extends TestCase
{
    /** @var array<string,array{key:OpenSSLAsymmetricKey,certificate:string}> */
    private static $identities = [];

    /** @return array{key:OpenSSLAsymmetricKey,certificate:string} */
    protected static function rsaIdentity(string $name = 'RSA Test'): array
    {
        return self::$identities['rsa:' . $name]
            ?? self::$identities['rsa:' . $name] = self::identity($name, OPENSSL_KEYTYPE_RSA);
    }

    /** @return array{key:OpenSSLAsymmetricKey,certificate:string} */
    protected static function ecIdentity(string $name = 'EC Test'): array
    {
        return self::$identities['ec:' . $name]
            ?? self::$identities['ec:' . $name] = self::identity($name, OPENSSL_KEYTYPE_EC);
    }

    /** @return array{key:OpenSSLAsymmetricKey,certificate:string} */
    private static function identity(string $name, int $type): array
    {
        $options = [
            'config' => __DIR__ . '/openssl.cnf',
            'private_key_type' => $type,
            'digest_alg' => 'sha256',
            'x509_extensions' => 'v3_cert',
        ];
        if ($type === OPENSSL_KEYTYPE_RSA) {
            $options['private_key_bits'] = 2048;
        } else {
            $options['curve_name'] = 'prime256v1';
        }
        $key = openssl_pkey_new($options);
        self::assertNotFalse($key);
        $csr = openssl_csr_new(['commonName' => $name], $key, $options);
        self::assertNotFalse($csr);
        $certificate = openssl_csr_sign($csr, null, $key, 2, $options, random_int(1, PHP_INT_MAX));
        self::assertNotFalse($certificate);
        self::assertTrue(openssl_x509_export($certificate, $pem));
        return ['key' => $key, 'certificate' => $pem];
    }

    protected static function content(): string
    {
        return "binary\0content\r\n" . hash('sha256', static::class, true);
    }

    protected static function replaceLast(string $data, string $search, string $replacement): string
    {
        $offset = strrpos($data, $search);
        self::assertNotFalse($offset, 'Expected DER fragment was not found');
        return substr_replace($data, $replacement, $offset, strlen($search));
    }

    protected static function mutateLastByte(string $data): string
    {
        $data[strlen($data) - 1] = chr(ord($data[strlen($data) - 1]) ^ 1);
        return $data;
    }

    protected static function inner(ContentInfo $contentInfo)
    {
        return $contentInfo->contentNode(new Decoder());
    }

    protected static function oid(string $oid): string
    {
        return Encoder::oid($oid);
    }
}
