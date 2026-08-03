<?php

declare(strict_types=1);

namespace PurePhpCms\Tests;

use PurePhpCms\Asn1\Decoder;
use PurePhpCms\Asn1\Encoder;
use PurePhpCms\Asn1\Node;
use PurePhpCms\Asn1\Values;
use PurePhpCms\Exception\CmsException;

final class Asn1Test extends CmsTestCase
{
    public function testPrimitiveAndConstructedRoundTrips(): void
    {
        $encoded = Encoder::sequence([
            Encoder::integer(65537),
            Encoder::octetString("a\0b"),
            Encoder::bitString("\xAA\x55"),
            Encoder::null(),
            Encoder::utcTime('260804120000Z'),
            Encoder::explicit(0, Encoder::integer(3)),
        ]);
        $root = (new Decoder())->decode($encoded);
        Values::expect($root, 0, 16, true);
        self::assertSame(65537, Values::integer($root->children[0]));
        self::assertSame("a\0b", Values::octetString($root->children[1]));
        self::assertSame("\xAA\x55", Values::bitString($root->children[2]));
        Values::expect($root->children[3], 0, 5, false);
        self::assertSame(2, $root->children[5]->class);
    }

    public function testLongLengthAndIndefiniteBer(): void
    {
        $value = str_repeat('x', 300);
        self::assertSame($value, Values::octetString((new Decoder())->decode(Encoder::octetString($value))));
        $ber = "\x24\x80\x04\x03abc\x04\x03def\x00\x00";
        self::assertSame('abcdef', Values::octetString((new Decoder())->decode($ber)));
    }

    public function testSetUsesDerLexicographicOrder(): void
    {
        $a = Encoder::integer(2);
        $b = Encoder::integer(1);
        $set = (new Decoder())->decode(Encoder::set([$a, $b]));
        self::assertSame([1, 2], array_map([Values::class, 'integer'], $set->children));
    }

    /** @dataProvider oidProvider */
    public function testOidRoundTrip(string $oid): void
    {
        self::assertSame($oid, Values::oid((new Decoder())->decode(Encoder::oid($oid))));
    }

    public function oidProvider(): array
    {
        return [['0.0'], ['1.2.840.113549.1.7.2'], ['2.999.3.40000']];
    }

    /** @dataProvider invalidOidTextProvider */
    public function testOidEncoderRejectsInvalidText(string $oid): void
    {
        $this->expectException(CmsException::class);
        Encoder::oid($oid);
    }

    public function invalidOidTextProvider(): array
    {
        return [[''], ['3.1'], ['1.40.1'], ['1.-1.2'], ['1.02.3'], ['1.a.2']];
    }

    /** @dataProvider malformedProvider */
    public function testDecoderRejectsMalformedInput(string $encoded): void
    {
        $this->expectException(CmsException::class);
        (new Decoder())->decode($encoded);
    }

    public function malformedProvider(): array
    {
        return [
            [''], ["\x30"], ["\x04\x80a\0\0"],
            ["\x30\x80\x02\x01\x00"], ["\x30\x03\x04\x02AB"],
            ["\x02\x81\x01\x01"], ["\x02\x82\x00\x80" . str_repeat("\0", 128)],
            [Encoder::integer(1) . Encoder::integer(2)],
        ];
    }

    public function testDecoderLimitsDepthAndNodes(): void
    {
        $nested = Encoder::sequence([Encoder::sequence([Encoder::integer(1)])]);
        try {
            (new Decoder(0, 100))->decode($nested);
            self::fail('Depth limit was not enforced');
        } catch (CmsException $expected) {
            self::assertStringContainsString('complexity', $expected->getMessage());
        }
        $this->expectException(CmsException::class);
        (new Decoder(10, 2))->decode(Encoder::sequence([Encoder::integer(1), Encoder::integer(2)]));
    }

    public function testHighTagDecodingAndInvalidHighTag(): void
    {
        $node = (new Decoder())->decode("\x9f\x20\x01x");
        self::assertSame(32, $node->tag);
        self::assertSame(2, $node->class);
        $this->expectException(CmsException::class);
        (new Decoder())->decode("\x1f\x80\x01\x00");
    }

    public function testValueReadersRejectWrongOrNonCanonicalValues(): void
    {
        $this->expectException(CmsException::class);
        Values::integer(new Node(2, 0, false, "\x80", "\x02\x01\x80", 0));
    }

    public function testOidRejectsUnterminatedAndNonMinimalArcs(): void
    {
        foreach (["\x06\x01\x80", "\x06\x02\x80\x00"] as $encoded) {
            try {
                Values::oid((new Decoder())->decode($encoded));
                self::fail('Invalid OID was accepted');
            } catch (CmsException $expected) {
                self::assertNotSame('', $expected->getMessage());
            }
        }
    }

    public function testOidRejectsOverflowWhenCombiningFirstTwoArcs(): void
    {
        $this->expectException(CmsException::class);
        Encoder::oid('2.' . PHP_INT_MAX);
    }

    public function testPemHelpers(): void
    {
        $der = Encoder::integer(7);
        $pem = Values::toPem('CMS', $der);
        self::assertSame($der, Values::decodePem($pem));
        self::assertSame($der, Values::decodePem($der));
        $this->expectException(CmsException::class);
        Values::decodePem("-----BEGIN CMS-----\n%%%\n-----END CMS-----");
    }
}
