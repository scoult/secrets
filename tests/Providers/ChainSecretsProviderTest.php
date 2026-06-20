<?php

declare(strict_types=1);

namespace Scoult\Secrets\Tests\Providers;

use PHPUnit\Framework\TestCase;
use Scoult\Secrets\Providers\ChainSecretsProvider;
use Scoult\Secrets\Providers\InMemorySecretsProvider;
use Scoult\Secrets\Exceptions\SecretProviderException;

class ChainSecretsProviderTest extends TestCase
{
    public function testChainingOrderAndFallback(): void
    {
        $provider1 = new InMemorySecretsProvider([
            'key1' => 'val1',
            'key_shared' => 'val_from_p1',
        ]);

        $provider2 = new InMemorySecretsProvider([
            'key2' => 'val2',
            'key_shared' => 'val_from_p2',
        ]);

        $chain = new ChainSecretsProvider([$provider1, $provider2]);

        // Key from provider 1
        $this->assertTrue($chain->has('key1'));
        $this->assertEquals('val1', $chain->get('key1'));

        // Key from provider 2
        $this->assertTrue($chain->has('key2'));
        $this->assertEquals('val2', $chain->get('key2'));

        // Shared key should return from the first provider that has it
        $this->assertTrue($chain->has('key_shared'));
        $this->assertEquals('val_from_p1', $chain->get('key_shared'));

        // Missing key
        $this->assertFalse($chain->has('missing'));
        $this->assertNull($chain->get('missing'));
    }

    public function testAddProvider(): void
    {
        $chain = new ChainSecretsProvider();
        $this->assertCount(0, $chain->getProviders());

        $provider = new InMemorySecretsProvider();
        $chain->addProvider($provider);

        $this->assertCount(1, $chain->getProviders());
        $this->assertSame($provider, $chain->getProviders()[0]);
    }

    public function testChainHandlesFailuresResilientlyByDefault(): void
    {
        $brokenProvider = new class extends InMemorySecretsProvider {
            public function get(string $key, array $options = []): ?string
            {
                throw new SecretProviderException('Service unavailable');
            }
            public function has(string $key, array $options = []): bool
            {
                throw new SecretProviderException('Service unavailable');
            }
        };

        $fallbackProvider = new InMemorySecretsProvider([
            'key' => 'fallback_value'
        ]);

        $chain = new ChainSecretsProvider([$brokenProvider, $fallbackProvider]);

        // Should ignore broken provider and fallback successfully
        $this->assertTrue($chain->has('key'));
        $this->assertEquals('fallback_value', $chain->get('key'));
    }

    public function testChainThrowsFailuresWhenConfigured(): void
    {
        $brokenProvider = new class extends InMemorySecretsProvider {
            public function get(string $key, array $options = []): ?string
            {
                throw new SecretProviderException('Service unavailable');
            }
            public function has(string $key, array $options = []): bool
            {
                throw new SecretProviderException('Service unavailable');
            }
        };

        $fallbackProvider = new InMemorySecretsProvider([
            'key' => 'fallback_value'
        ]);

        $chain = new ChainSecretsProvider([$brokenProvider, $fallbackProvider]);

        $this->expectException(SecretProviderException::class);
        $chain->get('key', ['ignore_chain_errors' => false]);
    }
}
