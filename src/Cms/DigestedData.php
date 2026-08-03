<?php

declare(strict_types=1);

namespace PurePhpCms\Cms;

use PurePhpCms\Asn1\Decoder;
use PurePhpCms\Asn1\Encoder;
use PurePhpCms\Asn1\Values;
use PurePhpCms\Exception\CmsException;

/** RFC 3852 DigestedData：提供不带身份认证的内容完整性检查。 */
final class DigestedData
{
    public static function create($content, $detached = false, $digestAlgorithm = 'sha256')
    {
        $algorithm = DigestAlgorithms::byName($digestAlgorithm);
        $algorithmIdentifier = Encoder::sequence([
            Encoder::oid($algorithm['oid']),
            Encoder::null(),
        ]);

        $encapsulatedFields = [Encoder::oid(ContentTypes::DATA)];
        if (!$detached) {
            $encapsulatedFields[] = Encoder::explicit(0, Encoder::octetString($content));
        }

        $value = Encoder::sequence([
            Encoder::integer(0),
            $algorithmIdentifier,
            Encoder::sequence($encapsulatedFields),
            Encoder::octetString(hash($algorithm['name'], $content, true)),
        ]);

        return new ContentInfo(ContentTypes::DIGESTED_DATA, $value);
    }

    public static function verify(ContentInfo $contentInfo, $externalContent = null, Decoder $decoder = null)
    {
        if ($contentInfo->contentType() !== ContentTypes::DIGESTED_DATA) {
            throw new CmsException('ContentInfo 不是 DigestedData');
        }

        $value = $contentInfo->contentNode($decoder);
        $algorithm = DigestAlgorithms::byOid(Values::oid($value->children[1]->children[0]));
        $encapsulatedContent = $value->children[2];

        if (isset($encapsulatedContent->children[1])) {
            $content = Values::octetString($encapsulatedContent->children[1]->children[0]);
            if ($externalContent !== null && !hash_equals($content, $externalContent)) {
                throw new CmsException('外部原文与 DigestedData 内嵌原文不一致');
            }
        } elseif ($externalContent !== null) {
            $content = $externalContent;
        } else {
            throw new CmsException('分离 DigestedData 必须提供外部原文');
        }

        $expectedDigest = Values::octetString($value->children[3]);
        $actualDigest = hash($algorithm['name'], $content, true);
        if (!hash_equals($expectedDigest, $actualDigest)) {
            throw new CmsException('DigestedData 摘要不匹配');
        }
        return $content;
    }
}
