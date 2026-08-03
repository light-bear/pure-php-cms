<?php

declare(strict_types=1);

namespace PurePhpCms\Asn1;

use PurePhpCms\Exception\CmsException;

final class Encoder
{
    /** 生成 DER 的 Tag-Length-Value。CMS 当前所需标签均小于 31。 */
    public static function tlv($tag, $content, $class = 0, $constructed = false)
    {
        if ($tag >= 31) throw new CmsException('High-tag encoding is not required by this CMS profile');
        $first = ($class << 6) | ($constructed ? 0x20 : 0) | $tag;
        return chr($first) . self::length(strlen($content)) . $content;
    }

    public static function sequence(array $items) { return self::tlv(16, implode('', $items), 0, true); }

    public static function set(array $items)
    {
        // DER 要求 SET OF 按“元素完整 DER 编码”的字典序排列。
        sort($items, SORT_STRING);
        return self::tlv(17, implode('', $items), 0, true);
    }

    public static function integerBytes($bytes)
    {
        // INTEGER 是有符号数；正整数最高位为 1 时必须补一个 00。
        $bytes = ltrim($bytes, "\0");
        if ($bytes === '') $bytes = "\0";
        if (ord($bytes[0]) & 0x80) $bytes = "\0" . $bytes;
        return self::tlv(2, $bytes);
    }

    public static function integer($number) { return self::integerBytes(self::unsignedInteger($number)); }
    public static function octetString($value) { return self::tlv(4, $value); }
    public static function bitString($value) { return self::tlv(3, "\0" . $value); }
    public static function null() { return self::tlv(5, ''); }
    public static function oid($oid) { return self::tlv(6, self::oidValue($oid)); }
    public static function utcTime($value) { return self::tlv(23, $value); }
    public static function explicit($tag, $encoded) { return self::tlv($tag, $encoded, 2, true); }
    public static function implicitConstructed($tag, $content) { return self::tlv($tag, $content, 2, true); }

    private static function length($length)
    {
        if ($length < 128) return chr($length);
        $bytes = '';
        while ($length > 0) { $bytes = chr($length & 0xff) . $bytes; $length >>= 8; }
        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    private static function oidValue($oid)
    {
        // OID 前两个节点合并，后续节点采用 base-128 可变长度编码。
        $parts = array_map('intval', explode('.', $oid));
        if (count($parts) < 2 || $parts[0] > 2 || $parts[1] > 39 && $parts[0] < 2) throw new CmsException('Invalid OID');
        $out = chr($parts[0] * 40 + $parts[1]);
        foreach (array_slice($parts, 2) as $part) {
            $chunk = chr($part & 0x7f);
            while (($part >>= 7) > 0) $chunk = chr(0x80 | ($part & 0x7f)) . $chunk;
            $out .= $chunk;
        }
        return $out;
    }

    private static function unsignedInteger($number)
    {
        if ($number < 0) throw new CmsException('Negative CMS version');
        $bytes = '';
        do { $bytes = chr($number & 0xff) . $bytes; $number >>= 8; } while ($number > 0);
        return $bytes;
    }
}
