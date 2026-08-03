<?php

declare(strict_types=1);

namespace PurePhpCms\Asn1;

use PurePhpCms\Exception\CmsException;

final class Decoder
{
    // 限制递归深度和节点总量，避免恶意 ASN.1 导致栈耗尽或内存耗尽。
    private $maxDepth;
    private $maxNodes;
    private $nodes = 0;

    public function __construct($maxDepth = 64, $maxNodes = 100000)
    {
        $this->maxDepth = $maxDepth;
        $this->maxNodes = $maxNodes;
    }

    public function decode($data)
    {
        if (!is_string($data)) {
            throw new CmsException('ASN.1 input must be a binary string');
        }
        $offset = 0;
        $this->nodes = 0;
        $node = $this->read($data, $offset, 0, strlen($data));
        if ($offset !== strlen($data)) {
            throw new CmsException('Trailing data after ASN.1 value');
        }
        return $node;
    }

    private function read($data, &$offset, $depth, $limit)
    {
        if ($depth > $this->maxDepth || ++$this->nodes > $this->maxNodes) {
            throw new CmsException('ASN.1 complexity limit exceeded');
        }
        $size = strlen($data);
        $start = $offset;
        if ($offset >= $limit || $limit > $size) throw new CmsException('Truncated ASN.1 tag');
        $first = ord($data[$offset++]);
        $class = $first >> 6;
        $constructed = (bool) ($first & 0x20);
        $tag = $first & 0x1f;
        // 低五位全为 1 时，后续字节使用 base-128 编码高标签号。
        if ($tag === 0x1f) {
            $tag = 0;
            do {
                if ($offset >= $limit) throw new CmsException('Truncated ASN.1 high tag');
                $byte = ord($data[$offset++]);
                if ($tag === 0 && ($byte & 0x7f) === 0) throw new CmsException('Non-minimal ASN.1 high tag');
                if ($tag > 0x1ffffff) throw new CmsException('ASN.1 tag is too large');
                $tag = ($tag << 7) | ($byte & 0x7f);
            } while ($byte & 0x80);
        }
        if ($offset >= $limit) throw new CmsException('Truncated ASN.1 length');
        $lengthByte = ord($data[$offset++]);
        // 0x80 表示 BER indefinite-length，只允许用于 constructed 类型。
        $indefinite = $lengthByte === 0x80;
        if ($indefinite && !$constructed) throw new CmsException('Primitive ASN.1 value has indefinite length');
        if (!$indefinite) {
            if (($lengthByte & 0x80) === 0) {
                $length = $lengthByte;
            } else {
                $count = $lengthByte & 0x7f;
                if ($count === 0 || $count > 4 || $offset + $count > $limit) throw new CmsException('Invalid ASN.1 length');
                if (ord($data[$offset]) === 0) throw new CmsException('Non-minimal ASN.1 length');
                $length = 0;
                for ($i = 0; $i < $count; $i++) $length = ($length << 8) | ord($data[$offset++]);
                if ($length < 128) throw new CmsException('Non-minimal ASN.1 length');
            }
            $contentEnd = $offset + $length;
            if ($contentEnd > $limit) throw new CmsException('ASN.1 value exceeds parent boundary');
        } else {
            $contentEnd = null;
        }
        $contentStart = $offset;
        $children = null;
        if ($constructed) {
            $children = [];
            while ($indefinite ? true : $offset < $contentEnd) {
                // BER 不定长结构使用 00 00（End-of-Contents）结束。
                if ($indefinite && $offset + 2 <= $limit && $data[$offset] === "\0" && $data[$offset + 1] === "\0") {
                    $contentEnd = $offset;
                    $offset += 2;
                    break;
                }
                if ($indefinite && $offset >= $limit) throw new CmsException('Unterminated ASN.1 value');
                $children[] = $this->read($data, $offset, $depth + 1, $indefinite ? $limit : $contentEnd);
            }
            if (!$indefinite && $offset !== $contentEnd) throw new CmsException('ASN.1 child exceeds parent boundary');
            if ($indefinite && $contentEnd === null) throw new CmsException('Unterminated ASN.1 value');
        } else {
            $offset = $contentEnd;
        }
        $value = substr($data, $contentStart, $contentEnd - $contentStart);
        return new Node($tag, $class, $constructed, $value, substr($data, $start, $offset - $start), $start, $children);
    }
}
