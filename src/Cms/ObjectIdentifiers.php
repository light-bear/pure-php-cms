<?php

declare(strict_types=1);

namespace PurePhpCms\Cms;

/** CMS SignedData 使用的对象标识符。 */
final class ObjectIdentifiers
{
    const DATA = ContentTypes::DATA;
    const SIGNED_DATA = ContentTypes::SIGNED_DATA;
    const CONTENT_TYPE = '1.2.840.113549.1.9.3';
    const MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
    const SIGNING_TIME = '1.2.840.113549.1.9.5';
    const COUNTER_SIGNATURE = '1.2.840.113549.1.9.6';
    const SHA1 = '1.3.14.3.2.26';
    const SHA256 = '2.16.840.1.101.3.4.2.1';
    const RSA_ENCRYPTION = '1.2.840.113549.1.1.1';
    const SHA1_WITH_RSA = '1.2.840.113549.1.1.5';
    const SHA256_WITH_RSA = '1.2.840.113549.1.1.11';
}
