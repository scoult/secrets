<?php

declare(strict_types=1);

namespace Scoult\Secrets\Providers;

use Scoult\Secrets\Contracts\SecretsProviderInterface;

/**
 * A secrets provider that reads from environment variables.
 */
class EnvSecretsProvider implements SecretsProviderInterface
{
    /**
     * @var string|null Prefix to prepend to keys before checking the environment.
     */
    private ?string $prefix;

    /**
     * @param string|null $prefix Optional prefix to prepend to keys (e.g., "APP_")
     */
    public function __construct(?string $prefix = null)
    {
        $this->prefix = $prefix;
    }

    public function get(string $key, array $options = []): ?string
    {
        $envKey = $this->resolveKey($key);

        // Try getenv()
        $value = getenv($envKey);
        if ($value !== false) {
            return $value;
        }

        // Try $_ENV superglobal
        if (isset($_ENV[$envKey])) {
            return (string) $_ENV[$envKey];
        }

        // Try $_SERVER superglobal
        if (isset($_SERVER[$envKey])) {
            return (string) $_SERVER[$envKey];
        }

        return null;
    }

    public function has(string $key, array $options = []): bool
    {
        $envKey = $this->resolveKey($key);

        return getenv($envKey) !== false
            || isset($_ENV[$envKey])
            || isset($_SERVER[$envKey]);
    }

    /**
     * Normalizes dot/hyphenated keys into uppercase underscore-separated names.
     * E.g., "database.host" -> "DATABASE_HOST"
     */
    private function resolveKey(string $key): string
    {
        $normalized = str_replace(['.', '-'], '_', strtoupper($key));
        return $this->prefix ? $this->prefix . $normalized : $normalized;
    }
}
