<?php

declare(strict_types=1);

namespace Scoult\Secrets\Contracts;

use Scoult\Secrets\Exceptions\SecretProviderException;

/**
 * Interface representing a mechanism to resolve a secret reference or URI to its actual value.
 */
interface SecretResolverInterface
{
    /**
     * Resolve the reference into the actual secret value.
     *
     * @param string $reference The secret reference (e.g. Key Vault reference JSON payload or URI).
     * @return string|null The resolved secret value, or null if it cannot be resolved.
     *
     * @throws SecretProviderException if the resolver encounters an error.
     */
    public function resolve(string $reference): ?string;
}
