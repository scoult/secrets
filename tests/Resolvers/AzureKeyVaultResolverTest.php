<?php

declare(strict_types=1);

namespace Scoult\Secrets\Tests\Resolvers;

use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Scoult\Secrets\Exceptions\SecretProviderException;
use Scoult\Secrets\Resolvers\AzureKeyVaultResolver;

class AzureKeyVaultResolverTest extends TestCase
{
    public function testResolveInvalidJsonReferenceReturnsNull(): void
    {
        $resolver = new AzureKeyVaultResolver('token123', $this->createMock(ClientInterface::class));

        // Not JSON
        $this->assertNull($resolver->resolve('not-json'));
        // JSON without uri
        $this->assertNull($resolver->resolve(json_encode(['foo' => 'bar'])));
    }

    public function testResolveSuccessWithStaticToken(): void
    {
        $refValue = json_encode(['uri' => 'https://myvault.vault.azure.net/secrets/mysecret/versionabc']);
        $mockResponseBody = json_encode([
            'value' => 'keyvault_secret_value',
            'id' => 'https://myvault.vault.azure.net/secrets/mysecret/versionabc'
        ]);

        $mockClient = $this->createMock(ClientInterface::class);
        $mockClient->expects($this->once())
            ->method('sendRequest')
            ->with($this->callback(function ($request) {
                // Verify request URI query string contains api-version
                $uri = (string) $request->getUri();
                $this->assertStringContainsString('api-version=7.4', $uri);

                // Verify Bearer authentication
                $this->assertTrue($request->hasHeader('Authorization'));
                $this->assertEquals('Bearer token123', $request->getHeaderLine('Authorization'));

                return true;
            }))
            ->willReturn(new Response(200, [], $mockResponseBody));

        $resolver = new AzureKeyVaultResolver('token123', $mockClient);
        $result = $resolver->resolve($refValue);

        $this->assertEquals('keyvault_secret_value', $result);
    }

    public function testResolveSuccessWithTokenCallback(): void
    {
        $refValue = json_encode(['uri' => 'https://myvault.vault.azure.net/secrets/mysecret/versionabc']);
        $mockResponseBody = json_encode(['value' => 'keyvault_secret_value']);

        $mockClient = $this->createMock(ClientInterface::class);
        $mockClient->expects($this->once())
            ->method('sendRequest')
            ->with($this->callback(function ($request) {
                $this->assertEquals('Bearer generated_token_abc', $request->getHeaderLine('Authorization'));
                return true;
            }))
            ->willReturn(new Response(200, [], $mockResponseBody));

        $tokenCallback = function () {
            return 'generated_token_abc';
        };

        $resolver = new AzureKeyVaultResolver($tokenCallback, $mockClient);
        $result = $resolver->resolve($refValue);

        $this->assertEquals('keyvault_secret_value', $result);
    }

    public function testResolveNotFoundReturnsNull(): void
    {
        $refValue = json_encode(['uri' => 'https://myvault.vault.azure.net/secrets/mysecret/versionabc']);

        $mockClient = $this->createMock(ClientInterface::class);
        $mockClient->expects($this->once())
            ->method('sendRequest')
            ->willReturn(new Response(404));

        $resolver = new AzureKeyVaultResolver('token123', $mockClient);
        $this->assertNull($resolver->resolve($refValue));
    }

    public function testResolveServerErrorThrowsException(): void
    {
        $refValue = json_encode(['uri' => 'https://myvault.vault.azure.net/secrets/mysecret/versionabc']);

        $mockClient = $this->createMock(ClientInterface::class);
        $mockClient->expects($this->once())
            ->method('sendRequest')
            ->willReturn(new Response(500, [], 'Internal Server Error'));

        $resolver = new AzureKeyVaultResolver('token123', $mockClient);

        $this->expectException(SecretProviderException::class);
        $this->expectExceptionMessage('Key Vault request failed with status code 500.');

        $resolver->resolve($refValue);
    }
}
