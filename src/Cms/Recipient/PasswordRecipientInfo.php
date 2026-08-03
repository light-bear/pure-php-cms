<?php

declare(strict_types=1);

namespace PurePhpCms\Cms\Recipient;

use PurePhpCms\Asn1\Encoder;
use PurePhpCms\Asn1\Node;
use PurePhpCms\Asn1\Values;
use PurePhpCms\Crypto\AesKeyWrap;
use PurePhpCms\Exception\CmsException;

/** PBKDF2-HMAC-SHA256 + AES Key Wrap 的 PasswordRecipientInfo。 */
final class PasswordRecipientInfo
{
    const MIN_ITERATIONS = 10000;
    const MAX_ITERATIONS = 2000000;
    const PBKDF2 = '1.2.840.113549.1.5.12';
    const HMAC_SHA256 = '1.2.840.113549.2.9';

    public static function create($password, $contentKey, $iterations = 100000)
    {
        self::assertIterations($iterations);
        $salt = random_bytes(16);
        $keyLength = 32;
        $derivedKey = hash_pbkdf2('sha256', $password, $salt, $iterations, $keyLength, true);

        $pbkdf2Parameters = Encoder::sequence([
            Encoder::octetString($salt),
            Encoder::integer($iterations),
            Encoder::integer($keyLength),
            Encoder::sequence([
                Encoder::oid(self::HMAC_SHA256),
                Encoder::null(),
            ]),
        ]);
        $keyDerivationAlgorithm = Encoder::sequence([
            Encoder::oid(self::PBKDF2),
            $pbkdf2Parameters,
        ]);

        $fields = [
            Encoder::integer(0),
            // [0] IMPLICIT AlgorithmIdentifier：替换 SEQUENCE 标签并保留其内容。
            Encoder::implicitConstructed(0, self::sequenceContent($keyDerivationAlgorithm)),
            Encoder::sequence([Encoder::oid(KekRecipientInfo::AES_256_WRAP)]),
            Encoder::octetString(AesKeyWrap::wrap($derivedKey, $contentKey)),
        ];
        return Encoder::implicitConstructed(3, implode('', $fields));
    }

    public static function unwrapKey(Node $recipientInfo, $password)
    {
        $keyDerivationAlgorithm = $recipientInfo->children[1];
        if (Values::oid($keyDerivationAlgorithm->children[0]) !== self::PBKDF2) {
            throw new CmsException('PasswordRecipientInfo 仅支持 PBKDF2');
        }
        $parameters = $keyDerivationAlgorithm->children[1];
        $salt = Values::octetString($parameters->children[0]);
        $iterations = Values::integer($parameters->children[1]);
        $keyLength = Values::integer($parameters->children[2]);
        if ($keyLength !== 32) {
            throw new CmsException('PasswordRecipientInfo PBKDF2 参数不安全或不受支持');
        }
        self::assertIterations($iterations);
        $prf = Values::oid($parameters->children[3]->children[0]);
        if ($prf !== self::HMAC_SHA256) {
            throw new CmsException('PasswordRecipientInfo 仅支持 HMAC-SHA256 PRF');
        }
        if (Values::oid($recipientInfo->children[2]->children[0]) !== KekRecipientInfo::AES_256_WRAP) {
            throw new CmsException('PasswordRecipientInfo 仅支持 AES-256 Key Wrap');
        }

        $derivedKey = hash_pbkdf2('sha256', $password, $salt, $iterations, 32, true);
        return AesKeyWrap::unwrap(
            $derivedKey,
            Values::octetString($recipientInfo->children[3])
        );
    }

    private static function sequenceContent($sequence)
    {
        $lengthByte = ord($sequence[1]);
        $headerLength = 2;
        if ($lengthByte & 0x80) {
            $headerLength += $lengthByte & 0x7f;
        }
        return substr($sequence, $headerLength);
    }

    private static function assertIterations($iterations)
    {
        if (!is_int($iterations)
            || $iterations < self::MIN_ITERATIONS
            || $iterations > self::MAX_ITERATIONS) {
            throw new CmsException(sprintf(
                'PBKDF2 迭代次数必须在 %d 到 %d 之间',
                self::MIN_ITERATIONS,
                self::MAX_ITERATIONS
            ));
        }
    }
}
