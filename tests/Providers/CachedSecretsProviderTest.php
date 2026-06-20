<?php

declare(strict_types=1);

namespace Scoult\Secrets\Tests\Providers;

use PHPUnit\Framework\TestCase;
use Psr\SimpleCache\CacheInterface;
use Scoult\Secrets\Providers\CachedSecretsProvider;
use Scoult\Secrets\Providers\InMemorySecretsProvider;

class CachedSecretsProviderTest extends TestCase
{
    private InMemoryCache $cache;
    private InMemorySecretsProvider $delegate;
    private CachedSecretsProvider $cachedProvider;

    protected function setUp(): void
    {
        $this->cache = new InMemoryCache();
        $this->delegate = new InMemorySecretsProvider([
            'database.password' => 'supersecret',
            'api.key' => 'tokenabc'
        ]);
        $this->cachedProvider = new CachedSecretsProvider($this->delegate, $this->cache);
    }

    public function testGetAndCacheHits(): void
    {
        // First get - cache miss, fetches from delegate
        $this->assertEquals('supersecret', $this->cachedProvider->get('database.password'));
        $this->assertCount(1, $this->cache->storage); // cache populated

        // Change delegate value
        $this->delegate->set('database.password', 'newsecret');

        // Second get - should hit cache and return the old cached value
        $this->assertEquals('supersecret', $this->cachedProvider->get('database.password'));

        // Invalidate cache
        $this->cachedProvider->invalidate('database.password');

        // Third get - cache miss, should fetch the new value from delegate
        $this->assertEquals('newsecret', $this->cachedProvider->get('database.password'));
    }

    public function testHasMaintainsCache(): void
    {
        $this->assertFalse($this->cache->has('scoult_secrets.database.password'));

        // calling has() should fetch and cache value
        $this->assertTrue($this->cachedProvider->has('database.password'));
        $this->assertTrue($this->cache->has('scoult_secrets.database.password'));
        $this->assertEquals('supersecret', $this->cache->get('scoult_secrets.database.password'));
    }
}

/**
 * A simple in-memory PSR-16 cache implementation for testing.
 */
class InMemoryCache implements CacheInterface
{
    public array $storage = [];

    public function get(string $key, mixed $default = null): mixed
    {
        return array_key_exists($key, $this->storage) ? $this->storage[$key] : $default;
    }

    public function set(string $key, mixed $value, \DateInterval|int|null $ttl = null): bool
    {
        $this->storage[$key] = $value;
        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->storage[$key]);
        return true;
    }

    public function clear(): bool
    {
        $this->storage = [];
        return true;
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $result = [];
        foreach ($keys as $key) {
            $result[$key] = $this->get($key, $default);
        }
        return $result;
    }

    public function setMultiple(iterable $values, \DateInterval|int|null $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            $this->set($key, $value, $ttl);
        }
        return true;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete($key);
        }
        return true;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->storage);
    }
}
