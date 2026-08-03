<?php

declare(strict_types=1);

namespace PurePhpCms\Cms;

use PurePhpCms\Asn1\Decoder;
use PurePhpCms\Asn1\Encoder;
use PurePhpCms\Asn1\Values;
use PurePhpCms\Cms\Recipient\KekRecipientInfo;
use PurePhpCms\Exception\CmsException;

/** RFC 3852 AuthenticatedData，当前使用 HMAC-SHA256 和 KEKRecipientInfo。 */
final class AuthenticatedData
{
    const HMAC_SHA256_OID = '1.2.840.113549.2.9';

    public static function create(
        $content,
        $keyIdentifier,
        $keyEncryptionKey,
        $detached = false
    ) {
        $macKey = random_bytes(32);
        $recipientInfo = KekRecipientInfo::create(
            $keyIdentifier,
            $keyEncryptionKey,
            $macKey
        );

        $encapsulatedFields = [Encoder::oid(ContentTypes::DATA)];
        if (!$detached) {
            $encapsulatedFields[] = Encoder::explicit(0, Encoder::octetString($content));
        }

        $value = Encoder::sequence([
            Encoder::integer(0),
            Encoder::set([$recipientInfo]),
            Encoder::sequence([
                Encoder::oid(self::HMAC_SHA256_OID),
                Encoder::null(),
            ]),
            Encoder::sequence($encapsulatedFields),
            Encoder::octetString(hash_hmac('sha256', $content, $macKey, true)),
        ]);

        return new ContentInfo(ContentTypes::AUTHENTICATED_DATA, $value);
    }

    public static function verify(
        ContentInfo $contentInfo,
        $keyIdentifier,
        $keyEncryptionKey,
        $externalContent = null,
        Decoder $decoder = null
    ) {
        if ($contentInfo->contentType() !== ContentTypes::AUTHENTICATED_DATA) {
            throw new CmsException('ContentInfo 不是 AuthenticatedData');
        }

        $authenticatedData = $contentInfo->contentNode($decoder);
        $fields = $authenticatedData->children;
        $recipientInfos = $fields[1];
        $macAlgorithm = $fields[2];
        $encapsulatedContent = $fields[3];
        $expectedMac = Values::octetString($fields[4]);

        if (Values::oid($macAlgorithm->children[0]) !== self::HMAC_SHA256_OID) {
            throw new CmsException('AuthenticatedData 使用了不支持的 MAC 算法');
        }

        $content = self::readContent($encapsulatedContent, $externalContent);
        $macKey = self::findMacKey(
            $recipientInfos,
            $keyIdentifier,
            $keyEncryptionKey
        );
        $actualMac = hash_hmac('sha256', $content, $macKey, true);
        if (!hash_equals($expectedMac, $actualMac)) {
            throw new CmsException('AuthenticatedData MAC 验证失败');
        }
        return $content;
    }

    private static function readContent($encapsulatedContent, $externalContent)
    {
        if (Values::oid($encapsulatedContent->children[0]) !== ContentTypes::DATA) {
            throw new CmsException('当前只支持认证 id-data 内容');
        }
        if (isset($encapsulatedContent->children[1])) {
            $content = Values::octetString($encapsulatedContent->children[1]->children[0]);
            if ($externalContent !== null && !hash_equals($content, $externalContent)) {
                throw new CmsException('外部原文与 AuthenticatedData 内嵌原文不一致');
            }
            return $content;
        }
        if ($externalContent === null) {
            throw new CmsException('分离 AuthenticatedData 必须提供外部原文');
        }
        return $externalContent;
    }

    private static function findMacKey($recipientInfos, $keyIdentifier, $keyEncryptionKey)
    {
        foreach ($recipientInfos->children as $recipientInfo) {
            if ($recipientInfo->class !== 2 || $recipientInfo->tag !== 2) {
                continue;
            }
            $key = KekRecipientInfo::unwrapKey(
                $recipientInfo,
                $keyIdentifier,
                $keyEncryptionKey
            );
            if ($key !== null) {
                return $key;
            }
        }
        throw new CmsException('AuthenticatedData 中没有匹配的 KEK 接收者');
    }
}
