<?php

declare(strict_types=1);

namespace PurePhpCms\Tests;

use PurePhpCms\Asn1\Decoder;
use PurePhpCms\Asn1\Encoder;
use PurePhpCms\Asn1\Values;
use PurePhpCms\Cms\ContentInfo;
use PurePhpCms\Cms\DataContent;
use PurePhpCms\Cms\EnvelopedData;
use PurePhpCms\Cms\Recipient\OtherRecipientInfo;
use PurePhpCms\Cms\Recipient\PasswordRecipientInfo;
use PurePhpCms\Crypto\AesKeyWrap;
use PurePhpCms\Exception\CmsException;

final class EnvelopedDataTest extends CmsTestCase
{
    public function testRsaSingleAndMultipleRecipients(): void
    {
        $first = self::rsaIdentity('Recipient One');
        $second = self::rsaIdentity('Recipient Two');
        $content = self::content();
        $envelope = EnvelopedData::encrypt($content, [$first['certificate'], $second['certificate']]);
        $decoded = ContentInfo::decode($envelope->encode());
        self::assertSame($content, EnvelopedData::decrypt($decoded, $first['certificate'], $first['key']));
        self::assertSame($content, EnvelopedData::decrypt($decoded, $second['certificate'], $second['key']));
    }

    public function testRsaRecipientFailures(): void
    {
        $recipient = self::rsaIdentity('Recipient');
        $other = self::rsaIdentity('Unrelated');
        $decoded = ContentInfo::decode(EnvelopedData::encrypt(self::content(), [$recipient['certificate']])->encode());
        foreach ([[$other['certificate'], $other['key']], [$recipient['certificate'], $other['key']]] as $pair) {
            try { EnvelopedData::decrypt($decoded, $pair[0], $pair[1]); self::fail(); }
            catch (CmsException $e) { self::assertNotSame('', $e->getMessage()); }
        }
        $this->expectException(CmsException::class);
        EnvelopedData::encrypt('x', []);
    }

    /** @dataProvider kekProvider */
    public function testKekRecipients(int $length): void
    {
        $content = self::content();
        $id = random_bytes(10);
        $kek = random_bytes($length);
        $envelope = EnvelopedData::encryptWithKek($content, $id, $kek);
        self::assertSame($content, EnvelopedData::decryptWithKek(ContentInfo::decode($envelope->encode()), $id, $kek));
        foreach ([[random_bytes(10), $kek], [$id, random_bytes($length)]] as $wrong) {
            try { EnvelopedData::decryptWithKek(ContentInfo::decode($envelope->encode()), $wrong[0], $wrong[1]); self::fail(); }
            catch (CmsException $e) { self::assertNotSame('', $e->getMessage()); }
        }
    }

    public function kekProvider(): array { return [[16], [24], [32]]; }

    public function testPasswordRecipientAndBounds(): void
    {
        $envelope = EnvelopedData::encryptWithPassword(self::content(), 'correct password', PasswordRecipientInfo::MIN_ITERATIONS);
        self::assertSame(self::content(), EnvelopedData::decryptWithPassword(ContentInfo::decode($envelope->encode()), 'correct password'));
        try { EnvelopedData::decryptWithPassword(ContentInfo::decode($envelope->encode()), 'wrong'); self::fail(); }
        catch (CmsException $e) { self::assertNotSame('', $e->getMessage()); }
        foreach ([PasswordRecipientInfo::MIN_ITERATIONS - 1, PasswordRecipientInfo::MAX_ITERATIONS + 1] as $iterations) {
            try { EnvelopedData::encryptWithPassword('x', 'p', $iterations); self::fail(); }
            catch (CmsException $e) { self::assertNotSame('', $e->getMessage()); }
        }
    }

    public function testOtherRecipientCallback(): void
    {
        $oid = '1.3.6.1.4.1.55555.1';
        $kek = random_bytes(32);
        $envelope = EnvelopedData::encryptWithOther(self::content(), static function ($cek) use ($oid, $kek) {
            return OtherRecipientInfo::create($oid, Encoder::octetString(AesKeyWrap::wrap($kek, $cek)));
        });
        $actual = EnvelopedData::decryptWithOther(ContentInfo::decode($envelope->encode()), static function ($type, $encoded) use ($oid, $kek) {
            self::assertSame($oid, $type);
            return AesKeyWrap::unwrap($kek, Values::octetString((new Decoder())->decode($encoded)));
        });
        self::assertSame(self::content(), $actual);
    }

    public function testP256KeyAgreement(): void
    {
        $originator = self::ecIdentity('ECDH Originator');
        $recipient = self::ecIdentity('ECDH Recipient');
        $envelope = EnvelopedData::encryptWithKeyAgreement(self::content(), $originator['key'], [$recipient['certificate']]);
        self::assertSame(self::content(), EnvelopedData::decryptWithKeyAgreement(ContentInfo::decode($envelope->encode()), $recipient['certificate'], $recipient['key']));
        $this->expectException(CmsException::class);
        EnvelopedData::encryptWithKeyAgreement('x', $originator['key'], []);
    }

    public function testAllDecryptorsRejectWrongContentType(): void
    {
        $data = DataContent::create('x');
        $recipient = self::rsaIdentity('Wrong Type');
        $operations = [
            static function () use ($data, $recipient): void { EnvelopedData::decrypt($data, $recipient['certificate'], $recipient['key']); },
            static function () use ($data): void { EnvelopedData::decryptWithKek($data, 'id', random_bytes(16)); },
            static function () use ($data): void { EnvelopedData::decryptWithPassword($data, 'p'); },
            static function () use ($data): void { EnvelopedData::decryptWithOther($data, static function (): void {}); },
        ];
        foreach ($operations as $operation) {
            try { $operation(); self::fail(); } catch (CmsException $e) { self::assertNotSame('', $e->getMessage()); }
        }
        self::assertTrue(true);
    }
}
