<?php

declare(strict_types=1);

namespace PurePhpCms\Cms;

use PurePhpCms\Asn1\Encoder;
use PurePhpCms\Asn1\Node;
use PurePhpCms\Asn1\Values;
use PurePhpCms\Exception\CmsException;

/** 负责创建和验证 RFC 5652 SignedAttributes。 */
final class SignedAttributes
{
    public static function create($content, array $algorithm, $signingTime = null)
    {
        $contentType = Encoder::sequence([
            Encoder::oid(ObjectIdentifiers::CONTENT_TYPE),
            Encoder::set([Encoder::oid(ObjectIdentifiers::DATA)]),
        ]);
        $messageDigest = Encoder::sequence([
            Encoder::oid(ObjectIdentifiers::MESSAGE_DIGEST),
            Encoder::set([Encoder::octetString(hash($algorithm['name'], $content, true))]),
        ]);

        $attributes = [$contentType, $messageDigest];
        if ($signingTime !== false) {
            $timestamp = $signingTime === null ? time() : (int) $signingTime;
            $attributes[] = Encoder::sequence([
                Encoder::oid(ObjectIdentifiers::SIGNING_TIME),
                Encoder::set([Encoder::utcTime(gmdate('ymdHis\\Z', $timestamp))]),
            ]);
        }
        sort($attributes, SORT_STRING);
        return implode('', $attributes);
    }

    public static function createCounterSignature($signatureValue, array $algorithm, $signingTime = null)
    {
        $messageDigest = Encoder::sequence([
            Encoder::oid(ObjectIdentifiers::MESSAGE_DIGEST),
            Encoder::set([
                Encoder::octetString(hash($algorithm['name'], $signatureValue, true)),
            ]),
        ]);
        $attributes = [$messageDigest];
        if ($signingTime !== false) {
            $timestamp = $signingTime === null ? time() : (int) $signingTime;
            $attributes[] = Encoder::sequence([
                Encoder::oid(ObjectIdentifiers::SIGNING_TIME),
                Encoder::set([Encoder::utcTime(gmdate('ymdHis\\Z', $timestamp))]),
            ]);
        }
        sort($attributes, SORT_STRING);
        return implode('', $attributes);
    }

    public static function verify(Node $signedAttributes, $content, array $algorithm)
    {
        $contentType = null;
        $messageDigest = null;
        $signingTime = null;

        foreach ($signedAttributes->children as $attribute) {
            $oid = Values::oid($attribute->children[0]);
            $values = $attribute->children[1]->children;
            if (count($values) !== 1) {
                throw new CmsException('签名属性必须只有一个值');
            }
            if ($oid === ObjectIdentifiers::CONTENT_TYPE) {
                $contentType = Values::oid($values[0]);
            } elseif ($oid === ObjectIdentifiers::MESSAGE_DIGEST) {
                $messageDigest = Values::octetString($values[0]);
            } elseif ($oid === ObjectIdentifiers::SIGNING_TIME) {
                if ($values[0]->class !== 0 || $values[0]->tag !== 23) {
                    throw new CmsException('signing-time 必须使用 UTCTime');
                }
                $signingTime = $values[0]->value;
            }
        }

        if ($contentType !== ObjectIdentifiers::DATA || $messageDigest === null) {
            throw new CmsException('CMS 缺少必需的签名属性');
        }

        $actualDigest = hash($algorithm['name'], $content, true);
        if (!hash_equals($actualDigest, $messageDigest)) {
            throw new CmsException('CMS 原文摘要不匹配');
        }
        return $signingTime;
    }

    public static function verifyCounterSignature(Node $attributes, $signatureValue, array $algorithm)
    {
        $messageDigest = null;
        $signingTime = null;
        foreach ($attributes->children as $attribute) {
            $oid = Values::oid($attribute->children[0]);
            $values = $attribute->children[1]->children;
            if (count($values) !== 1) throw new CmsException('反签名属性必须只有一个值');
            if ($oid === ObjectIdentifiers::CONTENT_TYPE) {
                throw new CmsException('countersignature 不得包含 content-type 属性');
            }
            if ($oid === ObjectIdentifiers::MESSAGE_DIGEST) {
                $messageDigest = Values::octetString($values[0]);
            } elseif ($oid === ObjectIdentifiers::SIGNING_TIME) {
                $signingTime = $values[0]->value;
            }
        }
        if ($messageDigest === null || !hash_equals(
            hash($algorithm['name'], $signatureValue, true),
            $messageDigest
        )) {
            throw new CmsException('countersignature 摘要不匹配');
        }
        return $signingTime;
    }

    /** SignerInfo 存储 A0 标签，密码学签名使用 Universal SET 标签。 */
    public static function signatureInput($attributesContent)
    {
        return Encoder::tlv(17, $attributesContent, 0, true);
    }
}
