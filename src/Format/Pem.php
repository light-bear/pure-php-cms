<?php

declare(strict_types=1);

namespace PurePhpCms\Format;

use PurePhpCms\Asn1\Values;

/** CMS DER/PEM 格式转换。 */
final class Pem
{
    public static function encode($der)
    {
        return Values::toPem('CMS', $der);
    }

    public static function decode($pemOrDer)
    {
        return Values::decodePem($pemOrDer);
    }
}
