<?php

declare(strict_types=1);

namespace PurePhpCms\Cms;

use PurePhpCms\Asn1\Decoder;
use PurePhpCms\Asn1\Encoder;
use PurePhpCms\Exception\CmsException;
use PurePhpCms\X509\CertificateInfo;

/** 按 RFC 5652 生成单签名者 SignedData。 */
final class SignedDataGenerator
{
    private $decoder;

    public function __construct(Decoder $decoder)
    {
        $this->decoder = $decoder;
    }

    public function generate($content, $certificate, $privateKey, $detached, $digestAlgorithm)
    {
        return $this->generateForSigners($content, [[
            'certificate' => $certificate,
            'privateKey' => $privateKey,
            'digest' => $digestAlgorithm,
        ]], $detached);
    }

    public function generateForSigners($content, array $signers, $detached)
    {
        if ($signers === []) {
            throw new CmsException('SignedData 至少需要一个签名者');
        }

        $digestIdentifiers = [];
        $signerInfos = [];
        $certificates = [];
        $signedDataVersion = 1;

        foreach ($signers as $signer) {
            $algorithm = DigestAlgorithms::byName(
                isset($signer['digest']) ? $signer['digest'] : 'sha256'
            );
            $certificate = CertificateInfo::load($signer['certificate'], $this->decoder);
            if ($certificate->publicKeyType() !== OPENSSL_KEYTYPE_RSA) {
                throw new CmsException('当前 SignedData 生成器仅支持 RSA 签名证书');
            }
            $attributesContent = SignedAttributes::create(
                $content,
                $algorithm,
                isset($signer['signingTime']) ? $signer['signingTime'] : null
            );
            $signature = $this->createSignature(
                $attributesContent,
                $signer['privateKey'],
                $algorithm
            );
            $digestIdentifier = $this->algorithmIdentifier($algorithm['oid']);
            $identifierType = isset($signer['identifier']) ? $signer['identifier'] : 'issuerAndSerial';
            if ($identifierType === 'subjectKeyIdentifier') {
                $signedDataVersion = 3;
            }

            $digestIdentifiers[$algorithm['oid']] = $digestIdentifier;
            $certificates[] = $certificate->der();
            $unsignedAttributes = null;
            if (isset($signer['counterSigner'])) {
                $counterSigner = $signer['counterSigner'];
                $counterAlgorithm = DigestAlgorithms::byName(
                    isset($counterSigner['digest']) ? $counterSigner['digest'] : 'sha256'
                );
                $counterCertificate = CertificateInfo::load(
                    $counterSigner['certificate'],
                    $this->decoder
                );
                if ($counterCertificate->publicKeyType() !== OPENSSL_KEYTYPE_RSA) {
                    throw new CmsException('当前 SignedData 生成器仅支持 RSA 反签名证书');
                }
                $counterAttributes = SignedAttributes::createCounterSignature(
                    $signature,
                    $counterAlgorithm,
                    isset($counterSigner['signingTime']) ? $counterSigner['signingTime'] : null
                );
                $counterSignature = $this->createSignature(
                    $counterAttributes,
                    $counterSigner['privateKey'],
                    $counterAlgorithm
                );
                $counterDigestIdentifier = $this->algorithmIdentifier($counterAlgorithm['oid']);
                $counterSignerInfo = $this->createSignerInfo(
                    $counterCertificate,
                    $counterDigestIdentifier,
                    $counterAttributes,
                    $counterSignature,
                    isset($counterSigner['identifier'])
                        ? $counterSigner['identifier']
                        : 'issuerAndSerial'
                );
                $counterSignatureAttribute = Encoder::sequence([
                    Encoder::oid(ObjectIdentifiers::COUNTER_SIGNATURE),
                    Encoder::set([$counterSignerInfo]),
                ]);
                $unsignedAttributes = $counterSignatureAttribute;
                $certificates[] = $counterCertificate->der();
                $digestIdentifiers[$counterAlgorithm['oid']] = $counterDigestIdentifier;
            }

            $signerInfos[] = $this->createSignerInfo(
                $certificate,
                $digestIdentifier,
                $attributesContent,
                $signature,
                $identifierType,
                $unsignedAttributes
            );
        }

        sort($certificates, SORT_STRING);

        $encapsulatedContent = $this->createEncapsulatedContent($content, $detached);
        $signedData = Encoder::sequence([
            Encoder::integer($signedDataVersion),
            Encoder::set(array_values($digestIdentifiers)),
            $encapsulatedContent,
            Encoder::implicitConstructed(0, implode('', $certificates)),
            Encoder::set($signerInfos),
        ]);

        return Encoder::sequence([
            Encoder::oid(ObjectIdentifiers::SIGNED_DATA),
            Encoder::explicit(0, $signedData),
        ]);
    }

    private function createSignature($attributesContent, $privateKey, array $algorithm)
    {
        $input = SignedAttributes::signatureInput($attributesContent);
        if (!openssl_sign($input, $signature, $privateKey, $algorithm['openssl'])) {
            throw new CmsException('OpenSSL 无法生成 CMS 数字签名');
        }
        return $signature;
    }

    private function createSignerInfo(
        CertificateInfo $certificate,
        $digestIdentifier,
        $attributesContent,
        $signature,
        $identifierType,
        $unsignedAttributes = null
    ) {
        if ($identifierType === 'subjectKeyIdentifier') {
            if ($certificate->subjectKeyIdentifier() === null) {
                throw new CmsException('签名证书没有 subjectKeyIdentifier 扩展');
            }
            $signerVersion = 3;
            $signerIdentifier = Encoder::tlv(
                0,
                $certificate->subjectKeyIdentifier(),
                2,
                false
            );
        } elseif ($identifierType === 'issuerAndSerial') {
            $signerVersion = 1;
            $signerIdentifier = Encoder::sequence([
                $certificate->issuer(),
                $certificate->serialNumber(),
            ]);
        } else {
            throw new CmsException('未知 SignerIdentifier 类型：' . $identifierType);
        }

        $fields = [
            Encoder::integer($signerVersion),
            $signerIdentifier,
            $digestIdentifier,
            Encoder::implicitConstructed(0, $attributesContent),
            $this->algorithmIdentifier($this->signatureAlgorithmOid($digestIdentifier)),
            Encoder::octetString($signature),
        ];
        if ($unsignedAttributes !== null) {
            $fields[] = Encoder::implicitConstructed(1, $unsignedAttributes);
        }
        return Encoder::sequence($fields);
    }

    private function createEncapsulatedContent($content, $detached)
    {
        $fields = [Encoder::oid(ObjectIdentifiers::DATA)];
        if (!$detached) {
            $fields[] = Encoder::explicit(0, Encoder::octetString($content));
        }
        return Encoder::sequence($fields);
    }

    private function algorithmIdentifier($oid)
    {
        return Encoder::sequence([Encoder::oid($oid), Encoder::null()]);
    }

    private function signatureAlgorithmOid($digestIdentifier)
    {
        $node = $this->decoder->decode($digestIdentifier);
        $digestOid = \PurePhpCms\Asn1\Values::oid($node->children[0]);
        if ($digestOid === ObjectIdentifiers::SHA1) return ObjectIdentifiers::SHA1_WITH_RSA;
        if ($digestOid === ObjectIdentifiers::SHA256) return ObjectIdentifiers::SHA256_WITH_RSA;
        throw new CmsException('没有与摘要算法匹配的 RSA 签名算法');
    }
}
