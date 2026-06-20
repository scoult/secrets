<?php

declare(strict_types=1);

namespace Scoult\Secrets\Providers;

use Scoult\Secrets\Contracts\SecretsProviderInterface;

/**
 * An in-memory/array-backed secrets provider.
 */
class InMemorySecretsProvider implements SecretsProviderInterface
{
    /**
     * @var array<string, string>
     */
    private array $secrets;

    /**
     * @param array<string, string> $secrets Initial secrets array.
     */
    public function __construct(array $secrets = [])
    {
        $this->secrets = $secrets;
    }

    public function get(string $key, array $options = []): ?string
    {
        return $this->secrets[$key] ?? null;
    }

    public function has(string $key, array $options = []): bool
    {
        return array_key_exists($key, $this->secrets);
    }

    /**
     * Set a secret value.
     */
    public function set(string $key, string $value): void
    {
        $this->secrets[$key] = $value;
    }

    /**
     * Remove a secret.
     */
    public function remove(string $key): void
    {
        unset($this->secrets[$key]);
    }
}
