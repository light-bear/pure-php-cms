<?php

declare(strict_types=1);

namespace PurePhpCms\Cms\Recipient;

use PurePhpCms\Asn1\Encoder;
use PurePhpCms\Asn1\Node;
use PurePhpCms\Asn1\Values;

/** OtherRecipientInfo 扩展容器；具体密码语义由 oriType 对应的外部规范定义。 */
final class OtherRecipientInfo
{
    public static function create($typeOid, $encodedValue)
    {
        return Encoder::implicitConstructed(
            4,
            Encoder::oid($typeOid) . $encodedValue
        );
    }

    public static function type(Node $recipientInfo)
    {
        return Values::oid($recipientInfo->children[0]);
    }

    public static function encodedValue(Node $recipientInfo)
    {
        return $recipientInfo->children[1]->raw;
    }
}
