<?php

declare(strict_types=1);

namespace PurePhpCms\Cms;

use PurePhpCms\Asn1\Decoder;
use PurePhpCms\Asn1\Encoder;
use PurePhpCms\Cms\Recipient\KeyTransRecipientInfo;
use PurePhpCms\Cms\Recipient\KeyAgreeRecipientInfo;
use PurePhpCms\Cms\Recipient\KekRecipientInfo;
use PurePhpCms\Cms\Recipient\OtherRecipientInfo;
use PurePhpCms\Cms\Recipient\PasswordRecipientInfo;
use PurePhpCms\Exception\CmsException;

/** 当前阶段的 EnvelopedData，支持一个或多个 RSA KeyTrans 接收者。 */
final class EnvelopedData
{
    public static function encrypt(
        $content,
        array $recipientCertificates,
        $contentEncryptionAlgorithm = 'aes-256-cbc',
        Decoder $decoder = null
    ) {
        if ($recipientCertificates === []) {
            throw new CmsException('EnvelopedData 至少需要一个接收者');
        }
        $decoder = $decoder ?: new Decoder();
        $algorithm = ContentEncryptionAlgorithms::byName($contentEncryptionAlgorithm);
        $contentEncryptionKey = random_bytes($algorithm['keyLength']);

        $recipientInfos = [];
        foreach ($recipientCertificates as $certificate) {
            $recipientInfos[] = KeyTransRecipientInfo::create(
                $contentEncryptionKey,
                $certificate,
                $decoder
            );
        }

        return self::createEnvelope(
            $content,
            $contentEncryptionKey,
            $recipientInfos,
            $contentEncryptionAlgorithm,
            0
        );
    }

    public static function encryptWithKek(
        $content,
        $keyIdentifier,
        $keyEncryptionKey,
        $contentEncryptionAlgorithm = 'aes-256-cbc'
    ) {
        $contentAlgorithm = ContentEncryptionAlgorithms::byName($contentEncryptionAlgorithm);
        $contentKey = random_bytes($contentAlgorithm['keyLength']);
        return self::createEnvelope(
            $content,
            $contentKey,
            [KekRecipientInfo::create($keyIdentifier, $keyEncryptionKey, $contentKey)],
            $contentEncryptionAlgorithm,
            2
        );
    }

    public static function encryptWithKeyAgreement(
        $content,
        $originatorPrivateKey,
        array $recipientCertificates,
        $contentEncryptionAlgorithm = 'aes-256-cbc',
        Decoder $decoder = null
    ) {
        if ($recipientCertificates === []) {
            throw new CmsException('KeyAgreeRecipientInfo 至少需要一个接收者');
        }
        $decoder = $decoder ?: new Decoder();
        $contentAlgorithm = ContentEncryptionAlgorithms::byName($contentEncryptionAlgorithm);
        $contentKey = random_bytes($contentAlgorithm['keyLength']);
        return self::createEnvelope(
            $content,
            $contentKey,
            [KeyAgreeRecipientInfo::create(
                $contentKey,
                $originatorPrivateKey,
                $recipientCertificates,
                $decoder
            )],
            $contentEncryptionAlgorithm,
            2
        );
    }

    public static function encryptWithPassword(
        $content,
        $password,
        $iterations = 100000,
        $contentEncryptionAlgorithm = 'aes-256-cbc'
    ) {
        $contentAlgorithm = ContentEncryptionAlgorithms::byName($contentEncryptionAlgorithm);
        $contentKey = random_bytes($contentAlgorithm['keyLength']);
        return self::createEnvelope(
            $content,
            $contentKey,
            [PasswordRecipientInfo::create($password, $contentKey, $iterations)],
            $contentEncryptionAlgorithm,
            2
        );
    }

    /** $recipientFactory 接收随机 CEK，并返回完整 OtherRecipientInfo 编码。 */
    public static function encryptWithOther(
        $content,
        callable $recipientFactory,
        $contentEncryptionAlgorithm = 'aes-256-cbc'
    ) {
        $contentAlgorithm = ContentEncryptionAlgorithms::byName($contentEncryptionAlgorithm);
        $contentKey = random_bytes($contentAlgorithm['keyLength']);
        $recipientInfo = $recipientFactory($contentKey);
        return self::createEnvelope(
            $content,
            $contentKey,
            [$recipientInfo],
            $contentEncryptionAlgorithm,
            2
        );
    }

    public static function decrypt(
        ContentInfo $contentInfo,
        $recipientCertificate,
        $recipientPrivateKey,
        Decoder $decoder = null
    ) {
        if ($contentInfo->contentType() !== ContentTypes::ENVELOPED_DATA) {
            throw new CmsException('ContentInfo 不是 EnvelopedData');
        }
        $decoder = $decoder ?: new Decoder();
        $envelopedData = $contentInfo->contentNode($decoder);
        $recipientInfos = $envelopedData->children[1];

        foreach ($recipientInfos->children as $recipientInfo) {
            // 无上下文标签的 SEQUENCE 表示 KeyTransRecipientInfo。
            if ($recipientInfo->class !== 0 || $recipientInfo->tag !== 16) {
                continue;
            }
            $key = KeyTransRecipientInfo::decryptKey(
                $recipientInfo,
                $recipientCertificate,
                $recipientPrivateKey,
                $decoder
            );
            if ($key !== null) {
                return EncryptedContentInfo::decrypt($envelopedData->children[2], $key);
            }
        }
        throw new CmsException('EnvelopedData 中没有匹配当前证书的接收者');
    }

    public static function decryptWithKek(
        ContentInfo $contentInfo,
        $keyIdentifier,
        $keyEncryptionKey,
        Decoder $decoder = null
    ) {
        return self::decryptWithResolver(
            $contentInfo,
            function ($recipientInfo) use ($keyIdentifier, $keyEncryptionKey) {
                if ($recipientInfo->class !== 2 || $recipientInfo->tag !== 2) return null;
                return KekRecipientInfo::unwrapKey(
                    $recipientInfo,
                    $keyIdentifier,
                    $keyEncryptionKey
                );
            },
            $decoder
        );
    }

    public static function decryptWithKeyAgreement(
        ContentInfo $contentInfo,
        $recipientCertificate,
        $recipientPrivateKey,
        Decoder $decoder = null
    ) {
        $decoder = $decoder ?: new Decoder();
        return self::decryptWithResolver(
            $contentInfo,
            function ($recipientInfo) use ($recipientCertificate, $recipientPrivateKey, $decoder) {
                if ($recipientInfo->class !== 2 || $recipientInfo->tag !== 1) return null;
                return KeyAgreeRecipientInfo::unwrapKey(
                    $recipientInfo,
                    $recipientCertificate,
                    $recipientPrivateKey,
                    $decoder
                );
            },
            $decoder
        );
    }

    public static function decryptWithPassword(
        ContentInfo $contentInfo,
        $password,
        Decoder $decoder = null
    ) {
        return self::decryptWithResolver(
            $contentInfo,
            function ($recipientInfo) use ($password) {
                if ($recipientInfo->class !== 2 || $recipientInfo->tag !== 3) return null;
                return PasswordRecipientInfo::unwrapKey($recipientInfo, $password);
            },
            $decoder
        );
    }

    /** $resolver 接收 OtherRecipientInfo 的 OID 与原始值，并返回 CEK。 */
    public static function decryptWithOther(
        ContentInfo $contentInfo,
        callable $resolver,
        Decoder $decoder = null
    ) {
        return self::decryptWithResolver(
            $contentInfo,
            function ($recipientInfo) use ($resolver) {
                if ($recipientInfo->class !== 2 || $recipientInfo->tag !== 4) return null;
                return $resolver(
                    OtherRecipientInfo::type($recipientInfo),
                    OtherRecipientInfo::encodedValue($recipientInfo)
                );
            },
            $decoder
        );
    }

    private static function createEnvelope(
        $content,
        $contentKey,
        array $recipientInfos,
        $contentEncryptionAlgorithm,
        $version
    ) {
        $value = Encoder::sequence([
            Encoder::integer($version),
            Encoder::set($recipientInfos),
            EncryptedContentInfo::encrypt(
                $content,
                $contentKey,
                $contentEncryptionAlgorithm
            ),
        ]);
        return new ContentInfo(ContentTypes::ENVELOPED_DATA, $value);
    }

    private static function decryptWithResolver(
        ContentInfo $contentInfo,
        callable $resolver,
        Decoder $decoder = null
    ) {
        if ($contentInfo->contentType() !== ContentTypes::ENVELOPED_DATA) {
            throw new CmsException('ContentInfo 不是 EnvelopedData');
        }
        $envelopedData = $contentInfo->contentNode($decoder);
        foreach ($envelopedData->children[1]->children as $recipientInfo) {
            $contentKey = $resolver($recipientInfo);
            if ($contentKey !== null) {
                return EncryptedContentInfo::decrypt($envelopedData->children[2], $contentKey);
            }
        }
        throw new CmsException('EnvelopedData 中没有可用的 RecipientInfo');
    }
}
