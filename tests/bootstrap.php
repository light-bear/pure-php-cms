<?php

declare(strict_types=1);

$autoload = __DIR__ . '/../vendor/autoload.php';
if (!is_file($autoload)) {
    throw new RuntimeException('Run composer install before executing the test suite.');
}
require $autoload;

error_reporting(E_ALL);
