<?php

declare(strict_types=1);

namespace Scoult\Secrets\Tests\Providers;

use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Scoult\Secrets\Contracts\SecretResolverInterface;
use Scoult\Secrets\Exceptions\SecretProviderException;
use Scoult\Secrets\Providers\AzureAppConfigurationProvider;

class AzureAppConfigurationProviderTest extends TestCase
{
    private string $connStr;

    protected function setUp(): void
    {
        $this->connStr = 'Endpoint=https://teststore.azconfig.io;Id=myId;Secret=bXlTZWNyZXRLZXlXaXRoRW5vdWdoQnl0ZXM=';
    }

    public function testInvalidConnectionStringThrowsException(): void
    {
        $this->expectException(SecretProviderException::class);
        $this->expectExceptionMessage('Invalid connection string. Must contain Endpoint, Id, and Secret.');

        new AzureAppConfigurationProvider('Endpoint=https://teststore.azconfig.io;Secret=abc');
    }

    public function testGetSuccess(): void
    {
        $mockBody = json_encode([
            'key' => 'db.password',
            'value' => 'secret_val_123',
            'content_type' => 'text/plain'
        ]);

        $mockClient = $this->createMock(ClientInterface::class);
        $mockClient->expects($this->once())
            ->method('sendRequest')
            ->willReturn(new Response(200, [], $mockBody));

        $provider = new AzureAppConfigurationProvider($this->connStr, $mockClient);
        $result = $provider->get('db.password');

        $this->assertEquals('secret_val_123', $result);
    }

    public function testGetNotFoundReturnsNull(): void
    {
        $mockClient = $this->createMock(ClientInterface::class);
        $mockClient->expects($this->once())
            ->method('sendRequest')
            ->willReturn(new Response(404));

        $provider = new AzureAppConfigurationProvider($this->connStr, $mockClient);
        $this->assertNull($provider->get('missing.key'));
    }

    public function testGetServerErrorThrowsException(): void
    {
        $mockClient = $this->createMock(ClientInterface::class);
        $mockClient->expects($this->once())
            ->method('sendRequest')
            ->willReturn(new Response(500, [], 'Internal Server Error'));

        $provider = new AzureAppConfigurationProvider($this->connStr, $mockClient);

        $this->expectException(SecretProviderException::class);
        $this->expectExceptionMessage('Azure App Configuration request failed with status code 500.');

        $provider->get('db.password');
    }

    public function testGetWithKeyVaultReference(): void
    {
        $refValue = json_encode(['uri' => 'https://myvault.vault.azure.net/secrets/dbpass/version']);
        $mockBody = json_encode([
            'key' => 'db.password',
            'value' => $refValue,
            'content_type' => 'application/vnd.microsoft.appconfig.keyvaultref+json;charset=utf-8'
        ]);

        $mockClient = $this->createMock(ClientInterface::class);
        $mockClient->method('sendRequest')
            ->willReturn(new Response(200, [], $mockBody));

        // Without resolver - returns raw JSON string
        $providerWithoutResolver = new AzureAppConfigurationProvider($this->connStr, $mockClient);
        $this->assertEquals($refValue, $providerWithoutResolver->get('db.password'));

        // With resolver - returns resolved value
        $mockResolver = $this->createMock(SecretResolverInterface::class);
        $mockResolver->expects($this->once())
            ->method('resolve')
            ->with($refValue)
            ->willReturn('resolved_keyvault_secret');

        $providerWithResolver = new AzureAppConfigurationProvider(
            $this->connStr,
            $mockClient,
            null,
            null,
            $mockResolver
        );

        $this->assertEquals('resolved_keyvault_secret', $providerWithResolver->get('db.password'));
    }

    public function testHas(): void
    {
        $mockClient = $this->createMock(ClientInterface::class);
        $mockClient->expects($this->exactly(2))
            ->method('sendRequest')
            ->willReturnOnConsecutiveCalls(
                new Response(200, [], json_encode(['key' => 'test', 'value' => 'val'])),
                new Response(404)
            );

        $provider = new AzureAppConfigurationProvider($this->connStr, $mockClient);

        $this->assertTrue($provider->has('test'));
        $this->assertFalse($provider->has('missing'));
    }

    public function testHmacHeadersAreGeneratedCorrectly(): void
    {
        $mockClient = $this->createMock(ClientInterface::class);
        $mockClient->expects($this->once())
            ->method('sendRequest')
            ->with($this->callback(function ($request) {
                // Verify standard headers are set
                $this->assertTrue($request->hasHeader('Host'));
                $this->assertEquals('teststore.azconfig.io', $request->getHeaderLine('Host'));

                $this->assertTrue($request->hasHeader('x-ms-date'));
                $this->assertTrue($request->hasHeader('x-ms-content-sha256'));

                $this->assertTrue($request->hasHeader('Authorization'));
                $auth = $request->getHeaderLine('Authorization');
                $this->assertStringStartsWith('HMAC-SHA256 Credential=myId', $auth);
                $this->assertStringContainsString('SignedHeaders=x-ms-date;host;x-ms-content-sha256', $auth);
                $this->assertStringContainsString('Signature=', $auth);

                return true;
            }))
            ->willReturn(new Response(200, [], json_encode(['key' => 'k', 'value' => 'v'])));

        $provider = new AzureAppConfigurationProvider($this->connStr, $mockClient);
        $provider->get('k');
    }
}
