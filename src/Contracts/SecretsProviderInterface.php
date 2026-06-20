<?php

declare(strict_types=1);

namespace Scoult\Secrets\Contracts;

use Scoult\Secrets\Exceptions\SecretProviderException;

/**
 * Interface representing a source for retrieving secrets.
 */
interface SecretsProviderInterface
{
    /**
     * Retrieve a secret value by its key.
     *
     * @param string $key The key/name of the secret to retrieve.
     * @param array<string, mixed> $options Provider-specific lookup options (e.g. ['label' => 'prod']).
     * @return string|null The secret value, or null if the secret does not exist.
     *
     * @throws SecretProviderException if the provider encounters a connection or runtime error.
     */
    public function get(string $key, array $options = []): ?string;

    /**
     * Determine if a secret with the given key exists in this provider.
     *
     * @param string $key The key/name of the secret.
     * @param array<string, mixed> $options Provider-specific lookup options.
     * @return bool True if the secret exists, false otherwise.
     *
     * @throws SecretProviderException if the provider encounters a connection or runtime error.
     */
    public function has(string $key, array $options = []): bool;
}
