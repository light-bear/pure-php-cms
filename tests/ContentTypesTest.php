<?php

declare(strict_types=1);

namespace PurePhpCms\Tests;

use PurePhpCms\Asn1\Encoder;
use PurePhpCms\Asn1\Decoder;
use PurePhpCms\Cms\AuthenticatedData;
use PurePhpCms\Cms\ContentEncryptionAlgorithms;
use PurePhpCms\Cms\ContentInfo;
use PurePhpCms\Cms\ContentTypes;
use PurePhpCms\Cms\DataContent;
use PurePhpCms\Cms\DigestedData;
use PurePhpCms\Cms\DigestAlgorithms;
use PurePhpCms\Cms\EncryptedData;
use PurePhpCms\Cms\EncryptedContentInfo;
use PurePhpCms\Exception\CmsException;

final class ContentTypesTest extends CmsTestCase
{
    public function testDataRoundTripAndWrongType(): void
    {
        $content = self::content();
        self::assertSame($content, DataContent::read(ContentInfo::decode(DataContent::create($content)->encode())));
        $this->expectException(CmsException::class);
        DataContent::read(new ContentInfo(ContentTypes::SIGNED_DATA, Encoder::octetString($content)));
    }

    /** @dataProvider digestProvider */
    public function testDigestedDataAttachedAndDetached(string $digest): void
    {
        $content = self::content();
        $attached = DigestedData::create($content, false, $digest);
        self::assertSame($content, DigestedData::verify(ContentInfo::decode($attached->encode())));
        self::assertSame($content, DigestedData::verify(ContentInfo::decode($attached->encode()), $content));
        $detached = DigestedData::create($content, true, $digest);
        self::assertSame($content, DigestedData::verify(ContentInfo::decode($detached->encode()), $content));
    }

    public function digestProvider(): array { return [['sha1'], ['sha256']]; }

    public function testDigestedDataFailures(): void
    {
        $content = self::content();
        $detached = DigestedData::create($content, true);
        foreach ([null, $content . '!'] as $external) {
            try { DigestedData::verify(ContentInfo::decode($detached->encode()), $external); self::fail(); }
            catch (CmsException $e) { self::assertNotSame('', $e->getMessage()); }
        }
        $tampered = self::mutateLastByte(DigestedData::create($content)->encode());
        $this->expectException(CmsException::class);
        DigestedData::verify(ContentInfo::decode($tampered));
    }

    public function testAlgorithmRegistries(): void
    {
        self::assertSame('sha256', DigestAlgorithms::byOid(DigestAlgorithms::byName('SHA256')['oid'])['name']);
        self::assertSame('aes-128-cbc', ContentEncryptionAlgorithms::byOid(ContentEncryptionAlgorithms::AES_128_CBC_OID)['name']);
        self::assertSame('aes-256-cbc', ContentEncryptionAlgorithms::byName('AES-256-CBC')['name']);
        foreach ([static function (): void { DigestAlgorithms::byName('md5'); }, static function (): void { DigestAlgorithms::byOid('1.2.3'); }, static function (): void { ContentEncryptionAlgorithms::byName('des'); }, static function (): void { ContentEncryptionAlgorithms::byOid('1.2.3'); }] as $operation) {
            try { $operation(); self::fail(); } catch (CmsException $e) { self::assertNotSame('', $e->getMessage()); }
        }
        $this->expectException(CmsException::class);
        ContentEncryptionAlgorithms::assertKeyLength('short', ContentEncryptionAlgorithms::byName('aes-128-cbc'));
    }

    /** @dataProvider cipherProvider */
    public function testEncryptedDataRoundTripAndFailures(string $cipher, int $keyLength): void
    {
        $content = self::content();
        $key = str_repeat("\x11", $keyLength);
        $encrypted = EncryptedData::encrypt($content, $key, $cipher);
        $decoded = ContentInfo::decode($encrypted->encode());
        self::assertSame($content, EncryptedData::decrypt($decoded, $key));
        try {
            $wrongPlaintext = EncryptedData::decrypt($decoded, random_bytes($keyLength));
            self::assertNotSame($content, $wrongPlaintext, 'AES-CBC wrong-key decryption reproduced the original plaintext');
        } catch (CmsException $e) {
            self::assertNotSame('', $e->getMessage());
        }
        try { EncryptedData::decrypt($decoded, random_bytes($keyLength === 16 ? 32 : 16)); self::fail(); }
        catch (CmsException $e) { self::assertNotSame('', $e->getMessage()); }
    }

    public function cipherProvider(): array { return [['aes-128-cbc', 16], ['aes-256-cbc', 32]]; }

    public function testEncryptedDataRejectsWrongContentType(): void
    {
        $this->expectException(CmsException::class);
        EncryptedData::decrypt(DataContent::create('x'), random_bytes(32));
    }

    public function testEncryptedContentInfoRejectsInvalidIvLength(): void
    {
        $key = random_bytes(32);
        $encrypted = (new Decoder())->decode(EncryptedContentInfo::encrypt('content', $key));
        $algorithm = $encrypted->children[1];
        $invalidAlgorithm = Encoder::sequence([
            $algorithm->children[0]->raw,
            Encoder::octetString(str_repeat("\0", 15)),
        ]);
        $invalid = (new Decoder())->decode(Encoder::sequence([
            $encrypted->children[0]->raw,
            $invalidAlgorithm,
            $encrypted->children[2]->raw,
        ]));

        $this->expectException(CmsException::class);
        EncryptedContentInfo::decrypt($invalid, $key);
    }

    public function testAuthenticatedDataAttachedDetachedAndFailures(): void
    {
        $content = self::content();
        $id = random_bytes(12);
        $kek = random_bytes(32);
        $attached = AuthenticatedData::create($content, $id, $kek);
        self::assertSame($content, AuthenticatedData::verify(ContentInfo::decode($attached->encode()), $id, $kek));
        self::assertSame($content, AuthenticatedData::verify(ContentInfo::decode($attached->encode()), $id, $kek, $content));
        $detached = AuthenticatedData::create($content, $id, $kek, true);
        self::assertSame($content, AuthenticatedData::verify(ContentInfo::decode($detached->encode()), $id, $kek, $content));

        $cases = [
            [$attached, random_bytes(12), $kek, null],
            [$attached, $id, random_bytes(32), null],
            [$attached, $id, $kek, $content . '!'],
            [$detached, $id, $kek, null],
        ];
        foreach ($cases as $case) {
            try { AuthenticatedData::verify(ContentInfo::decode($case[0]->encode()), $case[1], $case[2], $case[3]); self::fail(); }
            catch (CmsException $e) { self::assertNotSame('', $e->getMessage()); }
        }
        $tampered = self::mutateLastByte($attached->encode());
        $this->expectException(CmsException::class);
        AuthenticatedData::verify(ContentInfo::decode($tampered), $id, $kek);
    }
}
