<?php

declare(strict_types=1);

namespace PurePhpCms\Cms;

use PurePhpCms\Asn1\Decoder;
use PurePhpCms\Asn1\Encoder;
use PurePhpCms\Exception\CmsException;

/** RFC 3852 EncryptedData：密钥由 CMS 外部预先管理。 */
final class EncryptedData
{
    public static function encrypt($content, $key, $algorithm = 'aes-256-cbc')
    {
        $value = Encoder::sequence([
            Encoder::integer(0),
            EncryptedContentInfo::encrypt($content, $key, $algorithm),
        ]);
        return new ContentInfo(ContentTypes::ENCRYPTED_DATA, $value);
    }

    public static function decrypt(ContentInfo $contentInfo, $key, ?Decoder $decoder = null)
    {
        if ($contentInfo->contentType() !== ContentTypes::ENCRYPTED_DATA) {
            throw new CmsException('ContentInfo 不是 EncryptedData');
        }

        $encryptedData = $contentInfo->contentNode($decoder);
        return EncryptedContentInfo::decrypt($encryptedData->children[1], $key);
    }
}
