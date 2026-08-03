<?php

declare(strict_types=1);

namespace PurePhpCms;

final class VerificationResult
{
    // 验签成功后返回可信的原文、实际签名证书和摘要算法名称。
    public $content;
    public $certificatePem;
    public $digestAlgorithm;
    public $signingTime;
    public $counterSignature;

    public function __construct(
        $content,
        $certificatePem,
        $digestAlgorithm,
        $signingTime = null,
        $counterSignature = false
    )
    {
        $this->content = $content;
        $this->certificatePem = $certificatePem;
        $this->digestAlgorithm = $digestAlgorithm;
        $this->signingTime = $signingTime;
        $this->counterSignature = $counterSignature;
    }
}
