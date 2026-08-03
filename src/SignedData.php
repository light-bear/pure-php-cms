<?php

declare(strict_types=1);

namespace PurePhpCms;

use PurePhpCms\Asn1\Decoder;
use PurePhpCms\Asn1\Values;
use PurePhpCms\Cms\SignedDataGenerator;
use PurePhpCms\Cms\SignedDataVerifier;

/**
 * CMS SignedData 的对外入口。
 *
 * ASN.1 编解码、签名生成和验签分别由独立对象负责，使调用层不需要了解 CMS 字段细节。
 */
final class SignedData
{
    private $generator;
    private $verifier;

    public function __construct()
    {
        $decoder = new Decoder();
        $this->generator = new SignedDataGenerator($decoder);
        $this->verifier = new SignedDataVerifier($decoder);
    }

    /** 生成 DER 格式的封装签名或分离签名。 */
    public function sign($content, $certificate, $privateKey, $detached = true, $digest = 'sha256')
    {
        return $this->generator->generate(
            $content,
            $certificate,
            $privateKey,
            $detached,
            $digest
        );
    }

    /**
     * 使用多个签名者签署同一份内容。
     *
     * 每项包含 certificate、privateKey，可选 digest 和 signingTime。
     */
    public function signWithSigners($content, array $signers, $detached = true)
    {
        return $this->generator->generateForSigners($content, $signers, $detached);
    }

    /**
     * 验证 SignedData，并返回经过验证的原文和签名证书。
     *
     * @param string[] $externalCertificates CMS 未内嵌证书时的候选签名证书
     */
    public function verify($cms, $detachedContent = null, array $externalCertificates = [])
    {
        return $this->verifier->verify($cms, $detachedContent, $externalCertificates);
    }

    /** 验证所有 SignerInfo，并返回每个签名者的验证结果。 */
    public function verifyAll($cms, $detachedContent = null, array $externalCertificates = [])
    {
        return $this->verifier->verifyAll($cms, $detachedContent, $externalCertificates);
    }

    /** 将 DER SignedData 转换为 PEM，不改变内部 ASN.1 内容。 */
    public function toPem($der)
    {
        return Values::toPem('CMS', $der);
    }
}
