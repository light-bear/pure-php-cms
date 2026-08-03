<?php

declare(strict_types=1);

namespace PurePhpCms\Cms;

use PurePhpCms\Asn1\Decoder;
use PurePhpCms\Asn1\Encoder;
use PurePhpCms\Asn1\Values;
use PurePhpCms\Exception\CmsException;

/** RFC 3852 Data 内容类型，承载任意字节串。 */
final class DataContent
{
    public static function create($bytes)
    {
        return new ContentInfo(ContentTypes::DATA, Encoder::octetString($bytes));
    }

    public static function read(ContentInfo $contentInfo, ?Decoder $decoder = null)
    {
        if ($contentInfo->contentType() !== ContentTypes::DATA) {
            throw new CmsException('ContentInfo 不是 Data 类型');
        }
        return Values::octetString($contentInfo->contentNode($decoder));
    }
}
