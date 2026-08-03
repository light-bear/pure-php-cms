<?php

declare(strict_types=1);

namespace PurePhpCms\Cms;

use PurePhpCms\Asn1\Encoder;
use PurePhpCms\Asn1\Node;
use PurePhpCms\Asn1\Values;
use PurePhpCms\Exception\CmsException;

/** EncryptedData 与 EnvelopedData 共用的 EncryptedContentInfo。 */
final class EncryptedContentInfo
{
    public static function encrypt($content, $key, $algorithmName = 'aes-256-cbc')
    {
        $algorithm = ContentEncryptionAlgorithms::byName($algorithmName);
        ContentEncryptionAlgorithms::assertKeyLength($key, $algorithm);

        $iv = random_bytes($algorithm['ivLength']);
        $ciphertext = openssl_encrypt(
            $content,
            $algorithm['name'],
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );
        if ($ciphertext === false) {
            throw new CmsException('OpenSSL 内容加密失败');
        }

        return Encoder::sequence([
            Encoder::oid(ContentTypes::DATA),
            Encoder::sequence([
                Encoder::oid($algorithm['oid']),
                Encoder::octetString($iv),
            ]),
            // encryptedContent 是 [0] IMPLICIT OCTET STRING，因此使用 primitive 上下文标签。
            Encoder::tlv(0, $ciphertext, 2, false),
        ]);
    }

    public static function decrypt(Node $encryptedContentInfo, $key)
    {
        if (Values::oid($encryptedContentInfo->children[0]) !== ContentTypes::DATA) {
            throw new CmsException('当前只支持加密 id-data 内容');
        }

        $algorithmIdentifier = $encryptedContentInfo->children[1];
        $algorithm = ContentEncryptionAlgorithms::byOid(
            Values::oid($algorithmIdentifier->children[0])
        );
        ContentEncryptionAlgorithms::assertKeyLength($key, $algorithm);

        $iv = Values::octetString($algorithmIdentifier->children[1]);
        if (strlen($iv) !== $algorithm['ivLength']) {
            throw new CmsException('内容加密算法 IV 长度无效');
        }

        $encryptedContent = $encryptedContentInfo->children[2];
        if ($encryptedContent->class !== 2 || $encryptedContent->tag !== 0) {
            throw new CmsException('EncryptedContentInfo 缺少 encryptedContent');
        }

        $plaintext = openssl_decrypt(
            $encryptedContent->value,
            $algorithm['name'],
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );
        if ($plaintext === false) {
            throw new CmsException('内容解密失败，密钥、填充或密文无效');
        }
        return $plaintext;
    }
}
