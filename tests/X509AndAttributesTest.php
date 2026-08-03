<?php

declare(strict_types=1);

namespace PurePhpCms\Tests;

use PurePhpCms\Asn1\Decoder;
use PurePhpCms\Asn1\Encoder;
use PurePhpCms\Asn1\Values;
use PurePhpCms\Cms\DigestAlgorithms;
use PurePhpCms\Cms\ObjectIdentifiers;
use PurePhpCms\Cms\SignedAttributes;
use PurePhpCms\Exception\CmsException;
use PurePhpCms\VerificationResult;
use PurePhpCms\X509\CertificateInfo;

final class X509AndAttributesTest extends CmsTestCase
{
    public function testCertificateInfoFromPemAndDer(): void
    {
        $identity = self::rsaIdentity('Certificate Info');
        $pemInfo = CertificateInfo::load($identity['certificate'], new Decoder());
        $derInfo = CertificateInfo::load(Values::decodePem($identity['certificate']), new Decoder());
        self::assertSame($pemInfo->der(), $derInfo->der());
        self::assertSame(OPENSSL_KEYTYPE_RSA, $pemInfo->publicKeyType());
        self::assertNotSame('', $pemInfo->issuer());
        self::assertNotSame('', $pemInfo->serialNumber());
        self::assertNotNull($pemInfo->subjectKeyIdentifier());
        self::assertStringContainsString('BEGIN CERTIFICATE', $pemInfo->pem());
    }

    public function testCertificateIdentifierMatching(): void
    {
        $identity = self::rsaIdentity('Match Certificate');
        $info = CertificateInfo::load($identity['certificate'], new Decoder());
        $issuerAndSerial = (new Decoder())->decode(Encoder::sequence([$info->issuer(), $info->serialNumber()]));
        self::assertTrue($info->matches($issuerAndSerial));
        $ski = (new Decoder())->decode(Encoder::tlv(0, $info->subjectKeyIdentifier(), 2, false));
        self::assertTrue($info->matches($ski));
        $wrong = (new Decoder())->decode(Encoder::sequence([$info->issuer(), Encoder::integer(999)]));
        self::assertFalse($info->matches($wrong));
    }

    /** @dataProvider invalidCertificateProvider */
    public function testInvalidCertificatesAreRejected(string $certificate): void
    {
        $this->expectException(CmsException::class);
        CertificateInfo::load($certificate, new Decoder());
    }

    public function invalidCertificateProvider(): array
    {
        return [[''], [Encoder::sequence([])], [Encoder::sequence([Encoder::integer(1)])]];
    }

    public function testSignedAttributesCreateAndVerify(): void
    {
        $algorithm = DigestAlgorithms::byName('sha256');
        $content = self::content();
        $encodedContent = SignedAttributes::create($content, $algorithm, 1700000000);
        $node = (new Decoder())->decode(Encoder::implicitConstructed(0, $encodedContent));
        self::assertSame('231114221320Z', SignedAttributes::verify($node, $content, $algorithm));
        self::assertSame(Encoder::tlv(17, $encodedContent, 0, true), SignedAttributes::signatureInput($encodedContent));
    }

    public function testCounterSignatureAttributesAndDigestFailure(): void
    {
        $algorithm = DigestAlgorithms::byName('sha256');
        $signature = random_bytes(64);
        $encoded = SignedAttributes::createCounterSignature($signature, $algorithm, false);
        $node = (new Decoder())->decode(Encoder::implicitConstructed(0, $encoded));
        self::assertNull(SignedAttributes::verifyCounterSignature($node, $signature, $algorithm));
        $this->expectException(CmsException::class);
        SignedAttributes::verifyCounterSignature($node, $signature . 'x', $algorithm);
    }

    public function testVerificationResultFields(): void
    {
        $result = new VerificationResult('content', 'certificate', 'sha256', 'time', true);
        self::assertSame('content', $result->content);
        self::assertSame('certificate', $result->certificatePem);
        self::assertSame('sha256', $result->digestAlgorithm);
        self::assertSame('time', $result->signingTime);
        self::assertTrue($result->counterSignature);
    }
}
