<?php

declare(strict_types=1);

namespace Scoult\Secrets\Providers;

use Psr\SimpleCache\CacheInterface;
use Scoult\Secrets\Contracts\SecretsProviderInterface;

/**
 * A decorator provider that caches secrets retrieved from a delegate provider.
 */
class CachedSecretsProvider implements SecretsProviderInterface
{
    private SecretsProviderInterface $delegate;
    private CacheInterface $cache;
    private ?int $defaultTtl;
    private string $cacheKeyPrefix;

    /**
     * @param SecretsProviderInterface $delegate The underlying provider to fetch from.
     * @param CacheInterface $cache The PSR-16 cache implementation.
     * @param int|null $defaultTtl Default TTL in seconds.
     * @param string $cacheKeyPrefix Prefix to apply to all cache keys to avoid conflicts.
     */
    public function __construct(
        SecretsProviderInterface $delegate,
        CacheInterface $cache,
        ?int $defaultTtl = 3600,
        string $cacheKeyPrefix = 'scoult_secrets.'
    ) {
        $this->delegate = $delegate;
        $this->cache = $cache;
        $this->defaultTtl = $defaultTtl;
        $this->cacheKeyPrefix = $cacheKeyPrefix;
    }

    public function get(string $key, array $options = []): ?string
    {
        $cacheKey = $this->getCacheKey($key, $options);

        // Use a unique sentinel value to distinguish between a cached null and a cache miss
        $fallback = new \stdClass();
        $cachedValue = $this->cache->get($cacheKey, $fallback);

        if ($cachedValue !== $fallback) {
            return $cachedValue;
        }

        // Cache miss: fetch from delegate
        $value = $this->delegate->get($key, $options);

        // Store in cache (even if null)
        $ttl = $options['ttl'] ?? $this->defaultTtl;
        $this->cache->set($cacheKey, $value, $ttl);

        return $value;
    }

    public function has(string $key, array $options = []): bool
    {
        $cacheKey = $this->getCacheKey($key, $options);
        $fallback = new \stdClass();
        $cachedValue = $this->cache->get($cacheKey, $fallback);

        if ($cachedValue !== $fallback) {
            return $cachedValue !== null;
        }

        // Cache miss: delegate check
        $exists = $this->delegate->has($key, $options);
        $ttl = $options['ttl'] ?? $this->defaultTtl;

        if (!$exists) {
            $this->cache->set($cacheKey, null, $ttl);
        } else {
            // Eagerly fetch and cache the value to optimize subsequent get() calls
            $value = $this->delegate->get($key, $options);
            $this->cache->set($cacheKey, $value, $ttl);
        }

        return $exists;
    }

    /**
     * Clear the cache for a specific key.
     */
    public function invalidate(string $key, array $options = []): bool
    {
        return $this->cache->delete($this->getCacheKey($key, $options));
    }

    /**
     * Build a PSR-16 compliant cache key.
     * PSR-16 specifies that keys must only contain: a-z, A-Z, 0-9, _, and .
     */
    private function getCacheKey(string $key, array $options): string
    {
        $optionsHash = !empty($options) ? md5(serialize($options)) : '';
        $cleanKey = preg_replace('/[^a-zA-Z0-9_\.]/', '_', $key);
        return $this->cacheKeyPrefix . $cleanKey . ($optionsHash ? '.' . $optionsHash : '');
    }
}
