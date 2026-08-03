<?php

declare(strict_types=1);

namespace PurePhpCms\Cms\Recipient;

use PurePhpCms\Asn1\Encoder;
use PurePhpCms\Asn1\Node;
use PurePhpCms\Asn1\Values;
use PurePhpCms\Crypto\AesKeyWrap;
use PurePhpCms\Exception\CmsException;

/** 使用预共享 Key Encryption Key 的 KEKRecipientInfo。 */
final class KekRecipientInfo
{
    const AES_128_WRAP = '2.16.840.1.101.3.4.1.5';
    const AES_192_WRAP = '2.16.840.1.101.3.4.1.25';
    const AES_256_WRAP = '2.16.840.1.101.3.4.1.45';

    public static function create($keyIdentifier, $keyEncryptionKey, $contentKey)
    {
        $fields = [
            Encoder::integer(4),
            Encoder::sequence([Encoder::octetString($keyIdentifier)]),
            Encoder::sequence([Encoder::oid(self::oidForKey($keyEncryptionKey))]),
            Encoder::octetString(AesKeyWrap::wrap($keyEncryptionKey, $contentKey)),
        ];
        return Encoder::implicitConstructed(2, implode('', $fields));
    }

    public static function unwrapKey(Node $recipientInfo, $keyIdentifier, $keyEncryptionKey)
    {
        $encodedIdentifier = Values::octetString($recipientInfo->children[1]->children[0]);
        if (!hash_equals($encodedIdentifier, $keyIdentifier)) {
            return null;
        }
        $expectedOid = self::oidForKey($keyEncryptionKey);
        if (Values::oid($recipientInfo->children[2]->children[0]) !== $expectedOid) {
            throw new CmsException('KEKRecipientInfo 算法与提供的 KEK 长度不匹配');
        }
        return AesKeyWrap::unwrap(
            $keyEncryptionKey,
            Values::octetString($recipientInfo->children[3])
        );
    }

    private static function oidForKey($key)
    {
        switch (strlen($key)) {
            case 16: return self::AES_128_WRAP;
            case 24: return self::AES_192_WRAP;
            case 32: return self::AES_256_WRAP;
            default: throw new CmsException('KEK 必须为 16、24 或 32 字节');
        }
    }
}
