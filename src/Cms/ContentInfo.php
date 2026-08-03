<?php

declare(strict_types=1);

namespace PurePhpCms\Cms;

use PurePhpCms\Asn1\Decoder;
use PurePhpCms\Asn1\Encoder;
use PurePhpCms\Asn1\Node;
use PurePhpCms\Asn1\Values;
use PurePhpCms\Exception\CmsException;

/**
 * CMS 顶层保护内容。
 *
 * content 保留完整 ASN.1 TLV，使未知扩展内容也能无损解析和重新编码。
 */
final class ContentInfo
{
    private $contentType;
    private $content;

    public function __construct($contentType, $encodedContent)
    {
        $this->contentType = $contentType;
        $this->content = $encodedContent;
    }

    public static function decode($encoded, Decoder $decoder = null)
    {
        $decoder = $decoder ?: new Decoder();
        $root = $decoder->decode(Values::decodePem($encoded));
        Values::expect($root, 0, 16, true);

        if (count($root->children) !== 2) {
            throw new CmsException('ContentInfo 必须包含 contentType 和 content');
        }

        $contentType = Values::oid($root->children[0]);
        $wrapper = $root->children[1];
        Values::expect($wrapper, 2, 0, true);
        if (count($wrapper->children) !== 1) {
            throw new CmsException('ContentInfo.content 必须包含一个 ASN.1 值');
        }

        return new self($contentType, $wrapper->children[0]->raw);
    }

    public function encode()
    {
        return Encoder::sequence([
            Encoder::oid($this->contentType),
            Encoder::explicit(0, $this->content),
        ]);
    }

    public function contentType() { return $this->contentType; }
    public function contentTypeName() { return ContentTypes::name($this->contentType); }
    public function encodedContent() { return $this->content; }

    public function contentNode(Decoder $decoder = null)
    {
        return ($decoder ?: new Decoder())->decode($this->content);
    }
}
