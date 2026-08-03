<?php

declare(strict_types=1);

namespace PurePhpCms\Cms\Recipient;

use PurePhpCms\Asn1\Decoder;
use PurePhpCms\Asn1\Encoder;
use PurePhpCms\Asn1\Node;
use PurePhpCms\Asn1\Values;
use PurePhpCms\Cms\ObjectIdentifiers;
use PurePhpCms\Exception\CmsException;
use PurePhpCms\X509\CertificateInfo;

/** RSA KeyTransRecipientInfo：使用接收者证书公钥保护内容加密密钥。 */
final class KeyTransRecipientInfo
{
    public static function create($contentEncryptionKey, $recipientCertificate, Decoder $decoder)
    {
        $certificate = CertificateInfo::load($recipientCertificate, $decoder);
        $publicKey = openssl_pkey_get_public($certificate->pem());
        if ($publicKey === false || !openssl_public_encrypt(
            $contentEncryptionKey,
            $encryptedKey,
            $publicKey,
            OPENSSL_PKCS1_PADDING
        )) {
            throw new CmsException('RSA 接收者密钥加密失败');
        }

        return Encoder::sequence([
            Encoder::integer(0),
            Encoder::sequence([$certificate->issuer(), $certificate->serialNumber()]),
            Encoder::sequence([
                Encoder::oid(ObjectIdentifiers::RSA_ENCRYPTION),
                Encoder::null(),
            ]),
            Encoder::octetString($encryptedKey),
        ]);
    }

    public static function decryptKey(
        Node $recipientInfo,
        $recipientCertificate,
        $recipientPrivateKey,
        Decoder $decoder
    ) {
        $certificate = CertificateInfo::load($recipientCertificate, $decoder);
        if (!$certificate->matches($recipientInfo->children[1])) {
            return null;
        }

        $algorithmOid = Values::oid($recipientInfo->children[2]->children[0]);
        if ($algorithmOid !== ObjectIdentifiers::RSA_ENCRYPTION) {
            throw new CmsException('KeyTransRecipientInfo 使用了不支持的密钥算法');
        }

        $encryptedKey = Values::octetString($recipientInfo->children[3]);
        if (!openssl_private_decrypt(
            $encryptedKey,
            $contentEncryptionKey,
            $recipientPrivateKey,
            OPENSSL_PKCS1_PADDING
        )) {
            throw new CmsException('RSA 接收者密钥解密失败');
        }
        return $contentEncryptionKey;
    }
}
