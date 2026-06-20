<?php

declare(strict_types=1);

namespace Scoult\Secrets\Tests\Providers;

use Aws\Command;
use Aws\Exception\AwsException;
use Aws\MockHandler;
use Aws\Result;
use Aws\SecretsManager\SecretsManagerClient;
use PHPUnit\Framework\TestCase;
use Scoult\Secrets\Exceptions\SecretProviderException;
use Scoult\Secrets\Providers\AwsSecretsManagerProvider;

class AwsSecretsManagerProviderTest extends TestCase
{
    private function createMockClient(MockHandler $mockHandler): SecretsManagerClient
    {
        return new SecretsManagerClient([
            'region' => 'us-east-1',
            'version' => 'latest',
            'handler' => $mockHandler,
            'credentials' => false, // Disable loading credentials from environment/files during tests
        ]);
    }

    public function testConstructorAcceptsConfigArray(): void
    {
        $provider = new AwsSecretsManagerProvider([
            'region' => 'us-east-1',
            'version' => 'latest',
            'credentials' => false,
        ]);
        $this->assertInstanceOf(AwsSecretsManagerProvider::class, $provider);
    }

    public function testGetSecretStringSuccess(): void
    {
        $mockHandler = new MockHandler();
        $mockHandler->append(new Result([
            'SecretString' => 'plain_secret_value'
        ]));

        $client = $this->createMockClient($mockHandler);
        $provider = new AwsSecretsManagerProvider($client);

        $this->assertEquals('plain_secret_value', $provider->get('my-secret'));
    }

    public function testGetSecretJsonSuccess(): void
    {
        $mockHandler = new MockHandler();
        $mockHandler->append(new Result([
            'SecretString' => json_encode(['db_pass' => 'secret123'])
        ]));

        $client = $this->createMockClient($mockHandler);
        $provider = new AwsSecretsManagerProvider($client);

        // Fetch using option
        $this->assertEquals('secret123', $provider->get('my-secret', ['key' => 'db_pass']));
    }

    public function testGetSecretDelimitedSuccess(): void
    {
        $mockHandler = new MockHandler();
        $mockHandler->append(new Result([
            'SecretString' => json_encode(['db_pass' => 'secret123'])
        ]));

        $client = $this->createMockClient($mockHandler);
        $provider = new AwsSecretsManagerProvider($client);

        // Fetch using delimiter
        $this->assertEquals('secret123', $provider->get('my-secret:db_pass'));
    }

    public function testGetSecretNotFoundReturnsNull(): void
    {
        $mockHandler = new MockHandler();
        $command = new Command('GetSecretValue');
        $mockHandler->append(new AwsException(
            'Secret not found',
            $command,
            ['code' => 'ResourceNotFoundException']
        ));

        $client = $this->createMockClient($mockHandler);
        $provider = new AwsSecretsManagerProvider($client);

        $this->assertNull($provider->get('missing-secret'));
    }

    public function testGetSecretErrorThrowsException(): void
    {
        $mockHandler = new MockHandler();
        $command = new Command('GetSecretValue');
        $mockHandler->append(new AwsException(
            'Access denied',
            $command,
            ['code' => 'AccessDeniedException']
        ));

        $client = $this->createMockClient($mockHandler);
        $provider = new AwsSecretsManagerProvider($client);

        $this->expectException(SecretProviderException::class);
        $this->expectExceptionMessage('Failed to retrieve secret from AWS');

        $provider->get('restricted-secret');
    }

    public function testHasSuccess(): void
    {
        $mockHandler = new MockHandler();
        $mockHandler->append(new Result([
            'Name' => 'my-secret',
            'ARN' => 'arn:aws:secretsmanager:...'
        ]));

        $client = $this->createMockClient($mockHandler);
        $provider = new AwsSecretsManagerProvider($client);

        $this->assertTrue($provider->has('my-secret'));
    }

    public function testHasNotFoundReturnsFalse(): void
    {
        $mockHandler = new MockHandler();
        $command = new Command('DescribeSecret');
        $mockHandler->append(new AwsException(
            'Secret not found',
            $command,
            ['code' => 'ResourceNotFoundException']
        ));

        $client = $this->createMockClient($mockHandler);
        $provider = new AwsSecretsManagerProvider($client);

        $this->assertFalse($provider->has('missing-secret'));
    }
}
