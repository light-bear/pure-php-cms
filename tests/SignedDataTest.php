<?php

declare(strict_types=1);

namespace PurePhpCms\Tests;

use PurePhpCms\Asn1\Decoder;
use PurePhpCms\Asn1\Encoder;
use PurePhpCms\Asn1\Values;
use PurePhpCms\Cms\ContentInfo;
use PurePhpCms\Cms\ObjectIdentifiers;
use PurePhpCms\Exception\CmsException;
use PurePhpCms\SignedData;

final class SignedDataTest extends CmsTestCase
{
    /** @dataProvider digestProvider */
    public function testAttachedDetachedAndPem(string $digest): void
    {
        $identity = self::rsaIdentity('Signer');
        $cms = new SignedData();
        $content = self::content();
        $detached = $cms->sign($content, $identity['certificate'], $identity['key'], true, $digest);
        $result = $cms->verify($detached, $content);
        self::assertSame($content, $result->content);
        self::assertSame($digest, $result->digestAlgorithm);
        self::assertNotSame('', $result->certificatePem);
        self::assertFalse($result->counterSignature);
        self::assertSame($content, $cms->verify($cms->toPem($detached), $content)->content);
        $attached = $cms->sign($content, $identity['certificate'], $identity['key'], false, $digest);
        self::assertSame($content, $cms->verify($attached)->content);
    }

    public function digestProvider(): array { return [['sha1'], ['sha256']]; }

    public function testTamperedContentAndSignatureAreRejected(): void
    {
        $identity = self::rsaIdentity('Tamper Signer');
        $cms = new SignedData();
        $content = self::content();
        $signature = $cms->sign($content, $identity['certificate'], $identity['key']);
        foreach ([[$signature, $content . '!'], [self::mutateLastByte($signature), $content]] as $case) {
            try { $cms->verify($case[0], $case[1]); self::fail(); }
            catch (CmsException $e) { self::assertNotSame('', $e->getMessage()); }
        }
        $this->expectException(CmsException::class);
        $cms->verify($signature);
    }

    public function testSignatureAlgorithmMismatchAndMalformedCms(): void
    {
        $identity = self::rsaIdentity('Algorithm Signer');
        $cms = new SignedData();
        $signature = $cms->sign(self::content(), $identity['certificate'], $identity['key'], true, 'sha256');
        $tampered = self::replaceLast(
            $signature,
            Encoder::oid(ObjectIdentifiers::SHA256_WITH_RSA),
            Encoder::oid('1.2.840.113549.1.1.12')
        );
        try { $cms->verify($tampered, self::content()); self::fail(); }
        catch (CmsException $e) { self::assertStringContainsString('signatureAlgorithm', $e->getMessage()); }
        foreach (["\x30\x00", Encoder::integer(1)] as $malformed) {
            try { $cms->verify($malformed, 'x'); self::fail(); }
            catch (CmsException $e) { self::assertNotSame('', $e->getMessage()); }
        }
    }

    public function testMultipleSignersAndSigningTimes(): void
    {
        $first = self::rsaIdentity('First Signer');
        $second = self::rsaIdentity('Second Signer');
        $cms = new SignedData();
        $signed = $cms->signWithSigners(self::content(), [
            ['certificate' => $first['certificate'], 'privateKey' => $first['key'], 'digest' => 'sha1', 'signingTime' => 1700000000],
            ['certificate' => $second['certificate'], 'privateKey' => $second['key'], 'digest' => 'sha256', 'signingTime' => 1700000001],
        ]);
        $results = $cms->verifyAll($signed, self::content());
        self::assertCount(2, $results);
        $algorithms = [$results[0]->digestAlgorithm, $results[1]->digestAlgorithm];
        sort($algorithms);
        self::assertSame(['sha1', 'sha256'], $algorithms);
        self::assertNotNull($results[0]->signingTime);
        self::assertNotNull($results[1]->signingTime);
    }

    public function testSubjectKeyIdentifierAndVersion(): void
    {
        $identity = self::rsaIdentity('SKI Signer');
        $signed = (new SignedData())->signWithSigners(self::content(), [[
            'certificate' => $identity['certificate'], 'privateKey' => $identity['key'],
            'digest' => 'sha256', 'identifier' => 'subjectKeyIdentifier',
        ]], true);
        self::assertSame(self::content(), (new SignedData())->verify($signed, self::content())->content);
        $contentInfo = (new Decoder())->decode($signed);
        $signedData = $contentInfo->children[1]->children[0];
        self::assertSame(3, Values::integer($signedData->children[0]));
    }

    public function testCounterSignature(): void
    {
        $primary = self::rsaIdentity('Primary Signer');
        $counter = self::rsaIdentity('Counter Signer');
        $cms = new SignedData();
        $signed = $cms->signWithSigners(self::content(), [[
            'certificate' => $primary['certificate'], 'privateKey' => $primary['key'],
            'counterSigner' => ['certificate' => $counter['certificate'], 'privateKey' => $counter['key'], 'signingTime' => 1700000002],
        ]], true);
        $results = $cms->verifyAll($signed, self::content());
        self::assertCount(2, $results);
        self::assertFalse($results[0]->counterSignature);
        self::assertTrue($results[1]->counterSignature);
    }

    public function testGenerationRejectsInvalidConfigurations(): void
    {
        $rsa = self::rsaIdentity('Config Signer');
        $ec = self::ecIdentity('EC Signer');
        $cms = new SignedData();
        $operations = [
            static function () use ($cms): void { $cms->signWithSigners('x', []); },
            static function () use ($cms, $rsa): void { $cms->sign('x', $rsa['certificate'], $rsa['key'], true, 'md5'); },
            static function () use ($cms, $rsa): void { $cms->signWithSigners('x', [['certificate' => $rsa['certificate'], 'privateKey' => $rsa['key'], 'identifier' => 'invalid']]); },
            static function () use ($cms, $ec): void { $cms->sign('x', $ec['certificate'], $ec['key']); },
        ];
        foreach ($operations as $operation) {
            try { $operation(); self::fail(); } catch (CmsException $e) { self::assertNotSame('', $e->getMessage()); }
        }
        self::assertTrue(true);
    }
}
