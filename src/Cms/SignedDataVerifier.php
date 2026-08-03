<?php

declare(strict_types=1);

namespace PurePhpCms\Cms;

use PurePhpCms\Asn1\Decoder;
use PurePhpCms\Asn1\Node;
use PurePhpCms\Asn1\Values;
use PurePhpCms\Exception\CmsException;
use PurePhpCms\VerificationResult;
use PurePhpCms\X509\CertificateInfo;

/** 解析并验证 SignedData 中的全部签名者。 */
final class SignedDataVerifier
{
    private $decoder;

    public function __construct(Decoder $decoder)
    {
        $this->decoder = $decoder;
    }

    public function verify($encodedCms, $externalContent, array $externalCertificates)
    {
        $results = $this->verifyAll($encodedCms, $externalContent, $externalCertificates);
        return $results[0];
    }

    public function verifyAll($encodedCms, $externalContent, array $externalCertificates)
    {
        $signedData = $this->readSignedData($encodedCms);
        $fields = $signedData->children;
        $content = $this->readContent(
            $fields[Structure::SIGNED_DATA_ENCAP_CONTENT],
            $externalContent
        );

        list($certificateNodes, $signerInfos) = $this->readOptionalFields($fields);
        $certificates = $this->loadCertificates($certificateNodes, $externalCertificates);
        if ($signerInfos->children === []) {
            throw new CmsException('SignedData 至少需要一个 SignerInfo');
        }

        $results = [];
        foreach ($signerInfos->children as $signerInfo) {
            $results = array_merge(
                $results,
                $this->verifySigner($signerInfo, $content, $certificates, false)
            );
        }
        return $results;
    }

    private function verifySigner(
        Node $signerInfo,
        $signedValue,
        array $certificates,
        $counterSignature
    ) {
        $digestAlgorithm = $this->readDigestAlgorithm($signerInfo);
        $signedAttributes = $this->readSignedAttributes($signerInfo);
        $signingTime = $counterSignature
            ? SignedAttributes::verifyCounterSignature(
                $signedAttributes,
                $signedValue,
                $digestAlgorithm
            )
            : SignedAttributes::verify($signedAttributes, $signedValue, $digestAlgorithm);
        $certificate = $this->findSignerCertificate(
            $certificates,
            $signerInfo->children[Structure::SIGNER_IDENTIFIER]
        );
        $this->verifyDigitalSignature(
            $signerInfo,
            $signedAttributes,
            $certificate,
            $digestAlgorithm
        );

        $results = [new VerificationResult(
            $signedValue,
            $certificate->pem(),
            $digestAlgorithm['name'],
            $signingTime,
            $counterSignature
        )];
        $signatureValue = Values::octetString(
            $signerInfo->children[Structure::SIGNER_SIGNATURE]
        );
        foreach ($this->counterSignatures($signerInfo) as $counterSignerInfo) {
            $results = array_merge(
                $results,
                $this->verifySigner(
                    $counterSignerInfo,
                    $signatureValue,
                    $certificates,
                    true
                )
            );
        }
        return $results;
    }

    /** @return Node[] */
    private function counterSignatures(Node $signerInfo)
    {
        if (!isset($signerInfo->children[Structure::SIGNER_UNSIGNED_ATTRIBUTES])) {
            return [];
        }
        $unsignedAttributes = $signerInfo->children[Structure::SIGNER_UNSIGNED_ATTRIBUTES];
        if ($unsignedAttributes->class !== 2 || $unsignedAttributes->tag !== 1) {
            throw new CmsException('SignerInfo unsignedAttrs 标签无效');
        }

        $counterSignatures = [];
        foreach ($unsignedAttributes->children as $attribute) {
            if (Values::oid($attribute->children[0]) !== ObjectIdentifiers::COUNTER_SIGNATURE) {
                continue; // 未识别的 unsigned attribute 不参与签名，可安全保留并忽略。
            }
            foreach ($attribute->children[1]->children as $counterSignerInfo) {
                $counterSignatures[] = $counterSignerInfo;
            }
        }
        return $counterSignatures;
    }

    private function readSignedData($encodedCms)
    {
        $contentInfo = $this->decoder->decode(Values::decodePem($encodedCms));
        Values::expect($contentInfo, 0, 16, true);

        if (Values::oid($contentInfo->children[Structure::CONTENT_INFO_TYPE]) !== ObjectIdentifiers::SIGNED_DATA) {
            throw new CmsException('输入内容不是 CMS SignedData');
        }

        $wrapper = $contentInfo->children[Structure::CONTENT_INFO_CONTENT];
        Values::expect($wrapper, 2, 0, true);
        $signedData = $wrapper->children[0];
        Values::expect($signedData, 0, 16, true);
        return $signedData;
    }

    private function readContent(Node $encapsulatedContent, $externalContent)
    {
        if (Values::oid($encapsulatedContent->children[Structure::ENCAP_CONTENT_TYPE]) !== ObjectIdentifiers::DATA) {
            throw new CmsException('当前实现只支持 id-data 内容类型');
        }

        if (isset($encapsulatedContent->children[Structure::ENCAP_CONTENT])) {
            $contentWrapper = $encapsulatedContent->children[Structure::ENCAP_CONTENT];
            $content = Values::octetString($contentWrapper->children[0]);
            if ($externalContent !== null && !hash_equals($content, $externalContent)) {
                throw new CmsException('外部原文与 CMS 内嵌原文不一致');
            }
            return $content;
        }

        if ($externalContent === null) {
            throw new CmsException('分离签名必须提供外部原文');
        }
        return $externalContent;
    }

    private function readOptionalFields(array $fields)
    {
        $index = Structure::SIGNED_DATA_OPTIONAL_FIELDS_START;
        $certificateNodes = [];

        if ($this->isContextTag($fields, $index, 0)) {
            $certificateNodes = $fields[$index]->children ?: [];
            $index++;
        }
        if ($this->isContextTag($fields, $index, 1)) {
            $index++; // 当前版本忽略 CRL，但仍正确跳过该字段。
        }
        if (!isset($fields[$index])) {
            throw new CmsException('CMS 缺少 signerInfos');
        }

        return [$certificateNodes, $fields[$index]];
    }

    private function loadCertificates(array $nodes, array $externalCertificates)
    {
        $certificates = [];
        foreach ($nodes as $node) {
            $certificates[] = CertificateInfo::load($node->raw, $this->decoder);
        }
        foreach ($externalCertificates as $certificate) {
            $certificates[] = CertificateInfo::load($certificate, $this->decoder);
        }
        return $certificates;
    }

    private function readDigestAlgorithm(Node $signerInfo)
    {
        $algorithmIdentifier = $signerInfo->children[Structure::SIGNER_DIGEST_ALGORITHM];
        return DigestAlgorithms::byOid(Values::oid($algorithmIdentifier->children[0]));
    }

    private function readSignedAttributes(Node $signerInfo)
    {
        $signedAttributes = $signerInfo->children[Structure::SIGNER_SIGNED_ATTRIBUTES];
        Values::expect($signedAttributes, 2, 0, true);
        return $signedAttributes;
    }

    private function findSignerCertificate(array $certificates, Node $signerIdentifier)
    {
        foreach ($certificates as $certificate) {
            if ($certificate->matches($signerIdentifier)) {
                return $certificate;
            }
        }
        throw new CmsException('找不到与 SignerIdentifier 匹配的签名证书');
    }

    private function verifyDigitalSignature(
        Node $signerInfo,
        Node $signedAttributes,
        CertificateInfo $certificate,
        array $algorithm
    ) {
        $signature = Values::octetString($signerInfo->children[Structure::SIGNER_SIGNATURE]);
        $signatureInput = SignedAttributes::signatureInput($signedAttributes->value);
        $result = openssl_verify(
            $signatureInput,
            $signature,
            $certificate->pem(),
            $algorithm['openssl']
        );
        if ($result !== 1) {
            throw new CmsException('CMS 数字签名无效');
        }
    }

    private function isContextTag(array $fields, $index, $tag)
    {
        return isset($fields[$index])
            && $fields[$index]->class === 2
            && $fields[$index]->tag === $tag;
    }
}
