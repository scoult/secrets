<?php

declare(strict_types=1);

namespace Scoult\Secrets\Tests\Providers;

use PHPUnit\Framework\TestCase;
use Scoult\Secrets\Providers\InMemorySecretsProvider;

class InMemorySecretsProviderTest extends TestCase
{
    public function testGetAndHas(): void
    {
        $provider = new InMemorySecretsProvider([
            'database.password' => 'secret123',
            'api.key' => 'keyabc',
        ]);

        $this->assertTrue($provider->has('database.password'));
        $this->assertEquals('secret123', $provider->get('database.password'));

        $this->assertTrue($provider->has('api.key'));
        $this->assertEquals('keyabc', $provider->get('api.key'));

        $this->assertFalse($provider->has('non_existent'));
        $this->assertNull($provider->get('non_existent'));
    }

    public function testSetAndRemove(): void
    {
        $provider = new InMemorySecretsProvider();

        $this->assertFalse($provider->has('test'));
        $provider->set('test', 'value');
        $this->assertTrue($provider->has('test'));
        $this->assertEquals('value', $provider->get('test'));

        $provider->remove('test');
        $this->assertFalse($provider->has('test'));
        $this->assertNull($provider->get('test'));
    }
}
