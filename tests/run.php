<?php

declare(strict_types=1);

use PurePhpCms\Exception\CmsException;
use PurePhpCms\SignedData;
use PurePhpCms\Cms\ContentInfo;
use PurePhpCms\Cms\DataContent;
use PurePhpCms\Cms\DigestedData;
use PurePhpCms\Cms\EncryptedData;
use PurePhpCms\Cms\EnvelopedData;
use PurePhpCms\Cms\AuthenticatedData;
use PurePhpCms\Crypto\AesKeyWrap;
use PurePhpCms\Asn1\Decoder;
use PurePhpCms\Asn1\Encoder;
use PurePhpCms\Asn1\Values;
use PurePhpCms\Cms\Recipient\OtherRecipientInfo;
use PurePhpCms\Format\Pem;
use PurePhpCms\Format\Smime;

spl_autoload_register(function ($class) {
    $prefix = 'PurePhpCms\\';
    if (strpos($class, $prefix) === 0) {
        require __DIR__ . '/../src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
    }
});

function check($condition, $message)
{
    if (!$condition) throw new RuntimeException($message);
}

/** 断言调用必须抛出 CMS 异常，用于覆盖篡改、错密钥等失败路径。 */
function expectCmsFailure(callable $operation, $message)
{
    try {
        $operation();
    } catch (CmsException $expected) {
        return;
    }
    throw new RuntimeException($message);
}

/** 读取 ContentInfo 内层 CMS 对象的 version 字段。 */
function cmsVersion(ContentInfo $contentInfo)
{
    return Values::integer($contentInfo->contentNode()->children[0]);
}

// 测试运行时生成临时 RSA 身份，不依赖仓库中的固定私钥。
$options = [
    'config' => __DIR__ . '/openssl.cnf',
    'private_key_type' => OPENSSL_KEYTYPE_RSA,
    'private_key_bits' => 2048,
    'digest_alg' => 'sha256',
    'x509_extensions' => 'v3_cert',
];
$key = openssl_pkey_new($options);
check($key !== false, 'Could not generate RSA key');
$csr = openssl_csr_new(['commonName' => 'Pure PHP CMS'], $key, $options);
$certificate = openssl_csr_sign($csr, null, $key, 2, $options, 42);
check($certificate !== false, 'Could not generate certificate');
check(openssl_x509_export($certificate, $certificatePem), 'Could not export certificate');

$secondKey = openssl_pkey_new($options);
$secondCsr = openssl_csr_new(['commonName' => 'Second CMS Recipient'], $secondKey, $options);
$secondCertificate = openssl_csr_sign($secondCsr, null, $secondKey, 2, $options, 43);
check(openssl_x509_export($secondCertificate, $secondCertificatePem), 'Could not export second certificate');

$ecOptions = $options;
$ecOptions['private_key_type'] = OPENSSL_KEYTYPE_EC;
$ecOptions['curve_name'] = 'prime256v1';
unset($ecOptions['private_key_bits']);
$originatorEcKey = openssl_pkey_new($ecOptions);
$recipientEcKey = openssl_pkey_new($ecOptions);
$recipientEcCsr = openssl_csr_new(['commonName' => 'ECDH CMS Recipient'], $recipientEcKey, $ecOptions);
$recipientEcCertificate = openssl_csr_sign(
    $recipientEcCsr,
    null,
    $recipientEcKey,
    2,
    $ecOptions,
    44
);
check(
    openssl_x509_export($recipientEcCertificate, $recipientEcCertificatePem),
    'Could not export ECDH recipient certificate'
);

$cms = new SignedData();
$content = "binary\0content\r\n" . random_bytes(128);

// ContentInfo/Data 是所有 CMS 内容类型共用的顶层封装基础。
$dataContentInfo = DataContent::create($content);
$decodedDataContentInfo = ContentInfo::decode($dataContentInfo->encode());
check(DataContent::read($decodedDataContentInfo) === $content, 'CMS Data round trip failed');

$digested = DigestedData::create($content);
check(
    DigestedData::verify(ContentInfo::decode($digested->encode())) === $content,
    'CMS DigestedData round trip failed'
);
$detachedDigest = DigestedData::create($content, true);
check(
    DigestedData::verify(ContentInfo::decode($detachedDigest->encode()), $content) === $content,
    'CMS detached DigestedData verification failed'
);
expectCmsFailure(function () use ($detachedDigest, $content) {
    DigestedData::verify(ContentInfo::decode($detachedDigest->encode()), $content . 'changed');
}, 'DigestedData accepted modified detached content');

foreach (['aes-128-cbc' => 16, 'aes-256-cbc' => 32] as $cipher => $keyLength) {
    $contentEncryptionKey = random_bytes($keyLength);
    $encrypted = EncryptedData::encrypt($content, $contentEncryptionKey, $cipher);
    $decodedEncrypted = ContentInfo::decode($encrypted->encode());
    check(
        EncryptedData::decrypt($decodedEncrypted, $contentEncryptionKey) === $content,
        $cipher . ' EncryptedData round trip failed'
    );
    expectCmsFailure(function () use ($decodedEncrypted, $keyLength) {
        EncryptedData::decrypt($decodedEncrypted, random_bytes($keyLength));
    }, $cipher . ' EncryptedData accepted a wrong key');
}

$enveloped = EnvelopedData::encrypt($content, [$certificatePem, $secondCertificatePem]);
$decodedEnveloped = ContentInfo::decode($enveloped->encode());
check(
    EnvelopedData::decrypt($decodedEnveloped, $certificatePem, $key) === $content,
    'First EnvelopedData recipient could not decrypt'
);
check(
    EnvelopedData::decrypt($decodedEnveloped, $secondCertificatePem, $secondKey) === $content,
    'Second EnvelopedData recipient could not decrypt'
);
expectCmsFailure(function () use ($decodedEnveloped, $recipientEcCertificatePem, $recipientEcKey) {
    EnvelopedData::decrypt($decodedEnveloped, $recipientEcCertificatePem, $recipientEcKey);
}, 'KeyTrans EnvelopedData accepted an unrelated recipient');

// RFC 3394 官方常见长度的往返测试。
$keyEncryptionKey = random_bytes(32);
$keyToWrap = random_bytes(32);
check(
    AesKeyWrap::unwrap($keyEncryptionKey, AesKeyWrap::wrap($keyEncryptionKey, $keyToWrap)) === $keyToWrap,
    'AES Key Wrap round trip failed'
);

$kekIdentifier = random_bytes(16);
$authenticated = AuthenticatedData::create($content, $kekIdentifier, $keyEncryptionKey);
$decodedAuthenticated = ContentInfo::decode($authenticated->encode());
check(
    AuthenticatedData::verify($decodedAuthenticated, $kekIdentifier, $keyEncryptionKey) === $content,
    'AuthenticatedData verification failed'
);
expectCmsFailure(function () use ($decodedAuthenticated, $keyEncryptionKey) {
    AuthenticatedData::verify($decodedAuthenticated, random_bytes(16), $keyEncryptionKey);
}, 'AuthenticatedData accepted a wrong KEK identifier');
$modifiedAuthenticated = $authenticated->encode();
$modifiedAuthenticated[strlen($modifiedAuthenticated) - 1] =
    chr(ord($modifiedAuthenticated[strlen($modifiedAuthenticated) - 1]) ^ 1);
expectCmsFailure(function () use ($modifiedAuthenticated, $kekIdentifier, $keyEncryptionKey) {
    AuthenticatedData::verify(
        ContentInfo::decode($modifiedAuthenticated),
        $kekIdentifier,
        $keyEncryptionKey
    );
}, 'AuthenticatedData accepted a modified MAC');
$detachedAuthenticated = AuthenticatedData::create(
    $content,
    $kekIdentifier,
    $keyEncryptionKey,
    true
);
check(
    AuthenticatedData::verify(
        ContentInfo::decode($detachedAuthenticated->encode()),
        $kekIdentifier,
        $keyEncryptionKey,
        $content
    ) === $content,
    'Detached AuthenticatedData verification failed'
);

$kekEnveloped = EnvelopedData::encryptWithKek(
    $content,
    $kekIdentifier,
    $keyEncryptionKey
);
check(
    EnvelopedData::decryptWithKek(
        ContentInfo::decode($kekEnveloped->encode()),
        $kekIdentifier,
        $keyEncryptionKey
    ) === $content,
    'KEKRecipientInfo EnvelopedData failed'
);

$passwordEnveloped = EnvelopedData::encryptWithPassword($content, 'correct horse battery staple');
check(
    EnvelopedData::decryptWithPassword(
        ContentInfo::decode($passwordEnveloped->encode()),
        'correct horse battery staple'
    ) === $content,
    'PasswordRecipientInfo EnvelopedData failed'
);
expectCmsFailure(function () use ($passwordEnveloped) {
    EnvelopedData::decryptWithPassword(
        ContentInfo::decode($passwordEnveloped->encode()),
        'wrong password'
    );
}, 'PasswordRecipientInfo accepted a wrong password');

$otherType = '1.3.6.1.4.1.55555.1';
$otherKek = random_bytes(32);
$otherEnveloped = EnvelopedData::encryptWithOther(
    $content,
    function ($contentKey) use ($otherType, $otherKek) {
        return OtherRecipientInfo::create(
            $otherType,
            Encoder::octetString(AesKeyWrap::wrap($otherKek, $contentKey))
        );
    }
);
check(
    EnvelopedData::decryptWithOther(
        ContentInfo::decode($otherEnveloped->encode()),
        function ($type, $encodedValue) use ($otherType, $otherKek) {
            check($type === $otherType, 'OtherRecipientInfo OID mismatch');
            $wrappedKey = Values::octetString((new Decoder())->decode($encodedValue));
            return AesKeyWrap::unwrap($otherKek, $wrappedKey);
        }
    ) === $content,
    'OtherRecipientInfo EnvelopedData failed'
);

$keyAgreementEnveloped = EnvelopedData::encryptWithKeyAgreement(
    $content,
    $originatorEcKey,
    [$recipientEcCertificatePem]
);
check(
    EnvelopedData::decryptWithKeyAgreement(
        ContentInfo::decode($keyAgreementEnveloped->encode()),
        $recipientEcCertificatePem,
        $recipientEcKey
    ) === $content,
    'KeyAgreeRecipientInfo EnvelopedData failed'
);

// 同时覆盖旧系统常见 SHA-1 和推荐的 SHA-256。
foreach (['sha1', 'sha256'] as $digest) {
    $detached = $cms->sign($content, $certificatePem, $key, true, $digest);
    $result = $cms->verify($detached, $content);
    check($result->content === $content, $digest . ' detached content mismatch');
    check($result->digestAlgorithm === $digest, $digest . ' algorithm mismatch');

    $pem = $cms->toPem($detached);
    check($cms->verify($pem, $content)->content === $content, $digest . ' PEM verification failed');

    $attached = $cms->sign($content, $certificatePem, $key, false, $digest);
    check($cms->verify($attached)->content === $content, $digest . ' attached content mismatch');

    // 原文变化必须在 message-digest 检查阶段失败。
    try {
        $cms->verify($detached, $content . 'changed');
        throw new RuntimeException($digest . ' accepted modified content');
    } catch (CmsException $expected) {
    }

    // CMS 结构或签名值发生变化也必须失败。
    $modified = $detached;
    $modified[strlen($modified) - 10] = chr(ord($modified[strlen($modified) - 10]) ^ 1);
    try {
        $cms->verify($modified, $content);
        throw new RuntimeException($digest . ' accepted modified CMS');
    } catch (CmsException $expected) {
    }
}

$multiSigned = $cms->signWithSigners($content, [
    [
        'certificate' => $certificatePem,
        'privateKey' => $key,
        'digest' => 'sha1',
        'signingTime' => 1700000000,
    ],
    [
        'certificate' => $secondCertificatePem,
        'privateKey' => $secondKey,
        'digest' => 'sha256',
        'signingTime' => 1700000001,
    ],
]);
$multiResults = $cms->verifyAll($multiSigned, $content);
check(count($multiResults) === 2, 'SignedData multi-signer result count mismatch');
$multiAlgorithms = [$multiResults[0]->digestAlgorithm, $multiResults[1]->digestAlgorithm];
sort($multiAlgorithms);
check($multiAlgorithms === ['sha1', 'sha256'], 'SignedData multi-signer algorithms mismatch');
check(
    $multiResults[0]->signingTime !== null && $multiResults[1]->signingTime !== null,
    'SignedData signing-time attribute missing'
);

$skiSigned = $cms->signWithSigners($content, [[
    'certificate' => $certificatePem,
    'privateKey' => $key,
    'digest' => 'sha256',
    'identifier' => 'subjectKeyIdentifier',
]], true);
check(
    $cms->verify($skiSigned, $content)->content === $content,
    'SubjectKeyIdentifier signer verification failed'
);
check(cmsVersion(ContentInfo::decode($skiSigned)) === 3, 'SKI SignedData version must be 3');
check(cmsVersion($decodedEnveloped) === 0, 'KeyTrans EnvelopedData version must be 0');
check(
    cmsVersion(ContentInfo::decode($kekEnveloped->encode())) === 2,
    'KEK EnvelopedData version must be 2'
);

$counterSigned = $cms->signWithSigners($content, [[
    'certificate' => $certificatePem,
    'privateKey' => $key,
    'digest' => 'sha256',
    'counterSigner' => [
        'certificate' => $secondCertificatePem,
        'privateKey' => $secondKey,
        'digest' => 'sha256',
        'signingTime' => 1700000002,
    ],
]], true);
$counterResults = $cms->verifyAll($counterSigned, $content);
check(count($counterResults) === 2, 'Countersignature result count mismatch');
check($counterResults[0]->counterSignature === false, 'Primary signer marked as countersignature');
check($counterResults[1]->counterSignature === true, 'Countersigner was not identified');

$opaqueSmime = Smime::encode($cms->sign($content, $certificatePem, $key, false));
check(
    $cms->verify(Smime::decode($opaqueSmime))->content === $content,
    'Opaque S/MIME SignedData round trip failed'
);
$pemSigned = Pem::encode($cms->sign($content, $certificatePem, $key));
check($cms->verify(Pem::decode($pemSigned), $content)->content === $content, 'PEM format failed');

expectCmsFailure(function () {
    (new Decoder())->decode("\x30\x80\x02\x01\x00");
}, 'ASN.1 decoder accepted an unterminated indefinite-length value');

echo "All pure PHP CMS tests passed.\n";
