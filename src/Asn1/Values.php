<?php

declare(strict_types=1);

namespace PurePhpCms\Asn1;

use PurePhpCms\Exception\CmsException;

/** ASN.1 常用值的读取和格式转换，避免 CMS 代码直接操作标签细节。 */
final class Values
{
    public static function expect(Node $node, $class, $tag, $constructed)
    {
        if ($node->class !== $class || $node->tag !== $tag || $node->constructed !== $constructed) {
            throw new CmsException('ASN.1 结构与 CMS 定义不一致');
        }
    }

    public static function oid(Node $node)
    {
        self::expect($node, 0, 6, false);
        if ($node->value === '') {
            throw new CmsException('OID 内容为空');
        }

        $first = ord($node->value[0]);
        $parts = [$first < 80 ? intdiv($first, 40) : 2, $first < 80 ? $first % 40 : $first - 80];
        $value = 0;

        for ($index = 1, $length = strlen($node->value); $index < $length; $index++) {
            $byte = ord($node->value[$index]);
            $value = ($value << 7) | ($byte & 0x7f);
            if (($byte & 0x80) === 0) {
                $parts[] = $value;
                $value = 0;
            }
        }

        return implode('.', $parts);
    }

    public static function octetString(Node $node)
    {
        if ($node->class !== 0 || $node->tag !== 4) {
            throw new CmsException('期望 OCTET STRING');
        }
        if (!$node->constructed) {
            return $node->value;
        }

        $value = '';
        foreach ($node->children as $child) {
            $value .= self::octetString($child);
        }
        return $value;
    }

    public static function integer(Node $node)
    {
        self::expect($node, 0, 2, false);
        if ($node->value === '' || (ord($node->value[0]) & 0x80)) {
            throw new CmsException('当前 CMS 配置只接受非负 INTEGER');
        }
        $value = 0;
        for ($index = 0, $length = strlen($node->value); $index < $length; $index++) {
            if ($value > intdiv(PHP_INT_MAX - 255, 256)) {
                throw new CmsException('ASN.1 INTEGER 超出 PHP 整数范围');
            }
            $value = ($value << 8) | ord($node->value[$index]);
        }
        return $value;
    }

    public static function bitString(Node $node)
    {
        self::expect($node, 0, 3, false);
        if ($node->value === '' || ord($node->value[0]) !== 0) {
            throw new CmsException('仅支持无未使用位的 BIT STRING');
        }
        return substr($node->value, 1);
    }

    public static function decodePem($value)
    {
        if (strpos($value, '-----BEGIN') === false) {
            return $value;
        }
        $body = preg_replace('/-----[^-]+-----|\s+/', '', $value);
        $decoded = base64_decode($body, true);
        if ($decoded === false) {
            throw new CmsException('PEM Base64 内容无效');
        }
        return $decoded;
    }

    public static function toPem($label, $der)
    {
        return '-----BEGIN ' . $label . "-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . '-----END ' . $label . "-----\n";
    }
}
