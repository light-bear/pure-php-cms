<?php

declare(strict_types=1);

namespace PurePhpCms\X509;

use PurePhpCms\Asn1\Decoder;
use PurePhpCms\Asn1\Node;
use PurePhpCms\Asn1\Values;
use PurePhpCms\Exception\CmsException;

/** 提取 CMS SignerIdentifier 所需的证书 issuer 和 serialNumber。 */
final class CertificateInfo
{
    private $der;
    private $node;
    private $issuer;
    private $serialNumber;
    private $subjectKeyIdentifier;

    private function __construct($der, Node $node, $issuer, $serialNumber, $subjectKeyIdentifier)
    {
        $this->der = $der;
        $this->node = $node;
        $this->issuer = $issuer;
        $this->serialNumber = $serialNumber;
        $this->subjectKeyIdentifier = $subjectKeyIdentifier;
    }

    public static function load($certificate, Decoder $decoder)
    {
        try {
            $der = Values::decodePem($certificate);
            $node = $decoder->decode($der);
            Values::expect($node, 0, 16, true);
            if (!isset($node->children[0])) throw new CmsException('X.509 证书结构不完整');
            $tbsCertificate = $node->children[0];
            Values::expect($tbsCertificate, 0, 16, true);
            if (!isset($tbsCertificate->children[0])) throw new CmsException('X.509 证书结构不完整');
            $serialIndex = $tbsCertificate->children[0]->class === 2 ? 1 : 0;
            if (!isset($tbsCertificate->children[$serialIndex], $tbsCertificate->children[$serialIndex + 2])) {
                throw new CmsException('X.509 证书结构不完整');
            }
            $serialNumber = $tbsCertificate->children[$serialIndex];
            $issuer = $tbsCertificate->children[$serialIndex + 2];
        } catch (CmsException $error) {
            throw $error;
        } catch (\Throwable $error) {
            throw new CmsException('X.509 证书结构不完整');
        }

        $pem = Values::toPem('CERTIFICATE', $der);
        $parsed = openssl_x509_parse($pem);
        if ($parsed === false) throw new CmsException('OpenSSL 无法解析 X.509 证书');
        $skiText = isset($parsed['extensions']['subjectKeyIdentifier'])
            ? $parsed['extensions']['subjectKeyIdentifier']
            : null;
        $subjectKeyIdentifier = $skiText === null
            ? null
            : hex2bin(str_replace(':', '', $skiText));

        return new self(
            $der,
            $node,
            $issuer->raw,
            $serialNumber->raw,
            $subjectKeyIdentifier
        );
    }

    public function der() { return $this->der; }
    public function node() { return $this->node; }
    public function issuer() { return $this->issuer; }
    public function serialNumber() { return $this->serialNumber; }
    public function subjectKeyIdentifier() { return $this->subjectKeyIdentifier; }
    public function pem() { return Values::toPem('CERTIFICATE', $this->der); }

    public function publicKeyType()
    {
        $key = openssl_pkey_get_public($this->pem());
        $details = $key === false ? false : openssl_pkey_get_details($key);
        if ($details === false || !isset($details['type'])) {
            throw new CmsException('无法读取签名证书公钥类型');
        }
        return $details['type'];
    }

    public function matches(Node $issuerAndSerialNumber)
    {
        if ($issuerAndSerialNumber->class === 2 && $issuerAndSerialNumber->tag === 0) {
            return $this->subjectKeyIdentifier !== null
                && hash_equals($this->subjectKeyIdentifier, $issuerAndSerialNumber->value);
        }
        if ($issuerAndSerialNumber->class !== 0 || $issuerAndSerialNumber->tag !== 16
            || !isset($issuerAndSerialNumber->children[0], $issuerAndSerialNumber->children[1])) {
            throw new CmsException('SignerIdentifier 结构无效');
        }
        return hash_equals($this->issuer, $issuerAndSerialNumber->children[0]->raw)
            && hash_equals($this->serialNumber, $issuerAndSerialNumber->children[1]->raw);
    }
}
