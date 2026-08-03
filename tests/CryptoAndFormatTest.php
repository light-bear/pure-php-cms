<?php

declare(strict_types=1);

namespace PurePhpCms\Tests;

use PurePhpCms\Asn1\Encoder;
use PurePhpCms\Cms\ContentInfo;
use PurePhpCms\Cms\ContentTypes;
use PurePhpCms\Crypto\AesKeyWrap;
use PurePhpCms\Crypto\X963Kdf;
use PurePhpCms\Exception\CmsException;
use PurePhpCms\Format\Pem;
use PurePhpCms\Format\Smime;

final class CryptoAndFormatTest extends CmsTestCase
{
    /** @dataProvider rfc3394Provider */
    public function testRfc3394Vectors(string $kekHex, string $plainHex, string $wrappedHex): void
    {
        $kek = hex2bin($kekHex);
        $plain = hex2bin($plainHex);
        self::assertSame(strtolower($wrappedHex), bin2hex(AesKeyWrap::wrap($kek, $plain)));
        self::assertSame($plain, AesKeyWrap::unwrap($kek, hex2bin($wrappedHex)));
    }

    public function rfc3394Provider(): array
    {
        $plain = '00112233445566778899aabbccddeeff';
        return [
            ['000102030405060708090a0b0c0d0e0f', $plain, '1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5'],
            ['000102030405060708090a0b0c0d0e0f1011121314151617', $plain, '96778b25ae6ca435f92b5b97c050aed2468ab8a17ad84e5d'],
            ['000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', $plain, '64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7'],
        ];
    }

    public function testAesKeyWrapRejectsInvalidInputsAndTampering(): void
    {
        foreach ([[random_bytes(15), random_bytes(16)], [random_bytes(16), random_bytes(8)]] as $input) {
            try { AesKeyWrap::wrap($input[0], $input[1]); self::fail(); } catch (CmsException $e) { self::assertNotSame('', $e->getMessage()); }
        }
        $wrapped = AesKeyWrap::wrap(random_bytes(16), random_bytes(16));
        $this->expectException(CmsException::class);
        AesKeyWrap::unwrap(random_bytes(16), self::mutateLastByte($wrapped));
    }

    public function testX963KdfKnownOutputsAndLengths(): void
    {
        $expected = hash('sha256', 'secret' . pack('N', 1) . 'info', true)
            . hash('sha256', 'secret' . pack('N', 2) . 'info', true);
        self::assertSame(substr($expected, 0, 48), X963Kdf::derive('secret', 'info', 48));
        self::assertSame('', X963Kdf::derive('secret', 'info', 0));
    }

    public function testPemAndSmimeRoundTrips(): void
    {
        $der = Encoder::sequence([Encoder::integer(1)]);
        self::assertSame($der, Pem::decode(Pem::encode($der)));
        self::assertSame($der, Pem::decode($der));
        self::assertSame($der, Smime::decode(Smime::encode($der, 'enveloped-data')));
    }

    /** @dataProvider badFormatProvider */
    public function testFormatsRejectInvalidInput(callable $operation): void
    {
        $this->expectException(CmsException::class);
        $operation();
    }

    public function badFormatProvider(): array
    {
        return [
            [static function (): void { Pem::decode("-----BEGIN CMS-----\n%%%\n-----END CMS-----"); }],
            [static function (): void { Smime::decode('not mime'); }],
            [static function (): void { Smime::decode("Content-Type: application/pkcs7-mime\r\n\r\n%%%"); }],
        ];
    }

    public function testContentInfoAndContentTypes(): void
    {
        $info = new ContentInfo(ContentTypes::DATA, Encoder::octetString('x'));
        $decoded = ContentInfo::decode($info->encode());
        self::assertSame(ContentTypes::DATA, $decoded->contentType());
        self::assertSame('data', $decoded->contentTypeName());
        self::assertTrue(ContentTypes::isStandard(ContentTypes::SIGNED_DATA));
        self::assertFalse(ContentTypes::isStandard('1.2.3'));
        self::assertSame('unknown', (new ContentInfo('1.2.3', Encoder::null()))->contentTypeName());
    }

    /** @dataProvider malformedContentInfoProvider */
    public function testContentInfoRejectsMalformedStructures(string $der): void
    {
        $this->expectException(CmsException::class);
        ContentInfo::decode($der);
    }

    public function malformedContentInfoProvider(): array
    {
        return [
            [Encoder::integer(1)],
            [Encoder::sequence([Encoder::oid(ContentTypes::DATA)])],
            [Encoder::sequence([Encoder::oid(ContentTypes::DATA), Encoder::octetString('x')])],
            [Encoder::sequence([Encoder::oid(ContentTypes::DATA), Encoder::explicit(0, '')])],
        ];
    }
}
