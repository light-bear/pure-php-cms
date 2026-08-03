<?php

declare(strict_types=1);

namespace PurePhpCms\Cms\Recipient;

use PurePhpCms\Asn1\Decoder;
use PurePhpCms\Asn1\Encoder;
use PurePhpCms\Asn1\Node;
use PurePhpCms\Asn1\Values;
use PurePhpCms\Crypto\AesKeyWrap;
use PurePhpCms\Crypto\X963Kdf;
use PurePhpCms\Exception\CmsException;
use PurePhpCms\X509\CertificateInfo;

/** P-256 ECDH KeyAgreeRecipientInfo，使用 SHA-256 KDF 和 AES-256 Key Wrap。 */
final class KeyAgreeRecipientInfo
{
    const ECDH_SHA256_KDF = '1.3.132.1.11.1';

    public static function create(
        $contentKey,
        $originatorPrivateKey,
        array $recipientCertificates,
        Decoder $decoder
    ) {
        $originatorSpki = self::publicKeyInfo($originatorPrivateKey, $decoder);
        $keyWrapIdentifier = Encoder::sequence([
            Encoder::oid(KekRecipientInfo::AES_256_WRAP),
        ]);
        $keyAgreementIdentifier = Encoder::sequence([
            Encoder::oid(self::ECDH_SHA256_KDF),
            $keyWrapIdentifier,
        ]);
        $sharedInfo = self::sharedInfo($keyWrapIdentifier);

        $recipientEncryptedKeys = [];
        foreach ($recipientCertificates as $recipientCertificate) {
            $certificate = CertificateInfo::load($recipientCertificate, $decoder);
            $recipientPublicKey = openssl_pkey_get_public($certificate->pem());
            $sharedSecret = openssl_pkey_derive(
                $recipientPublicKey,
                $originatorPrivateKey,
                32
            );
            if ($sharedSecret === false) {
                throw new CmsException('ECDH 共享密钥计算失败');
            }
            $wrappingKey = X963Kdf::derive($sharedSecret, $sharedInfo, 32);
            $recipientEncryptedKeys[] = Encoder::sequence([
                Encoder::sequence([$certificate->issuer(), $certificate->serialNumber()]),
                Encoder::octetString(AesKeyWrap::wrap($wrappingKey, $contentKey)),
            ]);
        }

        $originatorKey = Encoder::implicitConstructed(
            1,
            $originatorSpki['algorithm'] . $originatorSpki['publicKey']
        );
        $fields = [
            Encoder::integer(3),
            Encoder::explicit(0, $originatorKey),
            $keyAgreementIdentifier,
            Encoder::sequence($recipientEncryptedKeys),
        ];
        return Encoder::implicitConstructed(1, implode('', $fields));
    }

    public static function unwrapKey(
        Node $recipientInfo,
        $recipientCertificate,
        $recipientPrivateKey,
        Decoder $decoder
    ) {
        $certificate = CertificateInfo::load($recipientCertificate, $decoder);
        $originatorKey = $recipientInfo->children[1]->children[0];
        $originatorPublicKey = self::publicKeyFromOriginator($originatorKey);
        $sharedSecret = openssl_pkey_derive(
            $originatorPublicKey,
            $recipientPrivateKey,
            32
        );
        if ($sharedSecret === false) {
            throw new CmsException('ECDH 共享密钥恢复失败');
        }

        $keyAgreementAlgorithm = $recipientInfo->children[2];
        if (Values::oid($keyAgreementAlgorithm->children[0]) !== self::ECDH_SHA256_KDF) {
            throw new CmsException('不支持的 KeyAgree KDF');
        }
        $keyWrapIdentifier = $keyAgreementAlgorithm->children[1];
        if (Values::oid($keyWrapIdentifier->children[0]) !== KekRecipientInfo::AES_256_WRAP) {
            throw new CmsException('KeyAgreeRecipientInfo 仅支持 AES-256 Key Wrap');
        }
        $wrappingKey = X963Kdf::derive(
            $sharedSecret,
            self::sharedInfo($keyWrapIdentifier->raw),
            32
        );

        foreach ($recipientInfo->children[3]->children as $recipientEncryptedKey) {
            if (!$certificate->matches($recipientEncryptedKey->children[0])) {
                continue;
            }
            return AesKeyWrap::unwrap(
                $wrappingKey,
                Values::octetString($recipientEncryptedKey->children[1])
            );
        }
        return null;
    }

    private static function publicKeyInfo($privateKey, Decoder $decoder)
    {
        $details = openssl_pkey_get_details($privateKey);
        if ($details === false || !isset($details['key'])) {
            throw new CmsException('无法导出 ECDH 发起方公钥');
        }
        $spki = $decoder->decode(Values::decodePem($details['key']));
        return [
            'algorithm' => $spki->children[0]->raw,
            'publicKey' => $spki->children[1]->raw,
        ];
    }

    private static function publicKeyFromOriginator(Node $originatorKey)
    {
        $spki = Encoder::sequence([
            $originatorKey->children[0]->raw,
            $originatorKey->children[1]->raw,
        ]);
        $publicKey = openssl_pkey_get_public(Values::toPem('PUBLIC KEY', $spki));
        if ($publicKey === false) {
            throw new CmsException('无法解析 ECDH 发起方公钥');
        }
        return $publicKey;
    }

    private static function sharedInfo($keyWrapIdentifier)
    {
        return Encoder::sequence([
            $keyWrapIdentifier,
            Encoder::explicit(2, Encoder::octetString(pack('N', 256))),
        ]);
    }
}
