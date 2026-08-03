<?php

declare(strict_types=1);

namespace PurePhpCms\Asn1;

final class Node
{
    // ASN.1 标签号、标签类别、是否为构造类型，以及解析后的原始内容。
    public $tag;
    public $class;
    public $constructed;
    public $value;
    public $raw;
    public $offset;
    /** @var Node[]|null */
    public $children;

    /**
     * 构造类型通过 children 保存子节点；primitive 类型的 children 为 null。
     * raw 始终保留收到的完整 TLV，验签时可避免重新编码造成字节变化。
     *
     * @param Node[]|null $children
     */
    public function __construct($tag, $class, $constructed, $value, $raw, $offset, ?array $children = null)
    {
        $this->tag = $tag;
        $this->class = $class;
        $this->constructed = $constructed;
        $this->value = $value;
        $this->raw = $raw;
        $this->offset = $offset;
        $this->children = $children;
    }
}
