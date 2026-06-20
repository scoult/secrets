<?php

declare(strict_types=1);

namespace Scoult\Secrets\Tests\Providers;

use PHPUnit\Framework\TestCase;
use Scoult\Secrets\Providers\EnvSecretsProvider;

class EnvSecretsProviderTest extends TestCase
{
    protected function setUp(): void
    {
        // Set environment variables for testing
        putenv('DATABASE_PASSWORD=env_secret_123');
        putenv('MY_APP_API_KEY=apikey_xyz');
    }

    protected function tearDown(): void
    {
        // Clean up environment variables
        putenv('DATABASE_PASSWORD');
        putenv('MY_APP_API_KEY');
    }

    public function testGetAndHasNormal(): void
    {
        $provider = new EnvSecretsProvider();

        $this->assertTrue($provider->has('database.password'));
        $this->assertEquals('env_secret_123', $provider->get('database.password'));

        $this->assertTrue($provider->has('database_password'));
        $this->assertEquals('env_secret_123', $provider->get('database_password'));

        $this->assertFalse($provider->has('non.existent'));
        $this->assertNull($provider->get('non.existent'));
    }

    public function testPrefix(): void
    {
        $provider = new EnvSecretsProvider('MY_APP_');

        $this->assertTrue($provider->has('api.key'));
        $this->assertEquals('apikey_xyz', $provider->get('api.key'));

        $this->assertFalse($provider->has('database.password'));
    }
}
