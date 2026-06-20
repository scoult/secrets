<?php

declare(strict_types=1);

namespace Scoult\Secrets\Exceptions;

/**
 * Exception thrown when a requested secret could not be found.
 */
class SecretNotFoundException extends SecretProviderException
{
    public function __construct(string $key, int $code = 0, ?\Throwable $previous = null)
    {
        parent::__construct(sprintf('Secret with key "%s" not found.', $key), $code, $previous);
    }
}
