<?php

declare(strict_types=1);

namespace PurePhpCms\Format;

use PurePhpCms\Exception\CmsException;

/** application/pkcs7-mime 的不透明 S/MIME 编码。 */
final class Smime
{
    public static function encode($der, $smimeType = 'signed-data')
    {
        return "MIME-Version: 1.0\r\n"
            . 'Content-Type: application/pkcs7-mime; smime-type=' . $smimeType
            . "; name=smime.p7m\r\n"
            . "Content-Transfer-Encoding: base64\r\n"
            . "Content-Disposition: attachment; filename=smime.p7m\r\n\r\n"
            . chunk_split(base64_encode($der), 64, "\r\n");
    }

    public static function decode($message)
    {
        $parts = preg_split("/\r?\n\r?\n/", $message, 2);
        if (count($parts) !== 2 || stripos($parts[0], 'application/pkcs7-mime') === false) {
            throw new CmsException('无效的 S/MIME CMS 消息');
        }
        $der = base64_decode(preg_replace('/\s+/', '', $parts[1]), true);
        if ($der === false) {
            throw new CmsException('S/MIME Base64 内容无效');
        }
        return $der;
    }
}
