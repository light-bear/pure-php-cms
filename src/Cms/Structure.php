<?php

declare(strict_types=1);

namespace PurePhpCms\Cms;

/** CMS SEQUENCE 字段位置，集中定义以避免业务代码出现无含义的数字下标。 */
final class Structure
{
    const CONTENT_INFO_TYPE = 0;
    const CONTENT_INFO_CONTENT = 1;

    const SIGNED_DATA_ENCAP_CONTENT = 2;
    const SIGNED_DATA_OPTIONAL_FIELDS_START = 3;

    const ENCAP_CONTENT_TYPE = 0;
    const ENCAP_CONTENT = 1;

    const SIGNER_IDENTIFIER = 1;
    const SIGNER_DIGEST_ALGORITHM = 2;
    const SIGNER_SIGNED_ATTRIBUTES = 3;
    const SIGNER_SIGNATURE = 5;
    const SIGNER_UNSIGNED_ATTRIBUTES = 6;
}
