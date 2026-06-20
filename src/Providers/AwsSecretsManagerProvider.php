<?php

declare(strict_types=1);

namespace Scoult\Secrets\Providers;

use Aws\Exception\AwsException;
use Aws\SecretsManager\SecretsManagerClient;
use Scoult\Secrets\Contracts\SecretsProviderInterface;
use Scoult\Secrets\Exceptions\SecretProviderException;

/**
 * Secrets provider integrating with AWS Secrets Manager.
 */
class AwsSecretsManagerProvider implements SecretsProviderInterface
{
    private SecretsManagerClient $client;

    /**
     * @param SecretsManagerClient|array<string, mixed> $clientOrConfig The AWS client or configuration array to create the client.
     */
    public function __construct(mixed $clientOrConfig)
    {
        if ($clientOrConfig instanceof SecretsManagerClient) {
            $this->client = $clientOrConfig;
        } elseif (is_array($clientOrConfig)) {
            $this->client = new SecretsManagerClient($clientOrConfig);
        } else {
            throw new \InvalidArgumentException(
                'Constructor expects an instance of Aws\SecretsManager\SecretsManagerClient or a configuration array.'
            );
        }
    }

    public function get(string $key, array $options = []): ?string
    {
        [$secretId, $jsonKey] = $this->parseKey($key, $options);

        try {
            $result = $this->client->getSecretValue([
                'SecretId' => $secretId,
            ]);

            $secretString = $result['SecretString'] ?? null;

            if ($secretString === null) {
                return null;
            }

            if ($jsonKey !== null) {
                $decoded = json_decode($secretString, true);
                if (json_last_error() !== JSON_ERROR_NONE) {
                    throw new SecretProviderException(
                        sprintf('Failed to parse JSON secret string: %s', json_last_error_msg())
                    );
                }
                return $decoded[$jsonKey] ?? null;
            }

            return $secretString;

        } catch (AwsException $e) {
            if ($e->getAwsErrorCode() === 'ResourceNotFoundException') {
                return null;
            }
            throw new SecretProviderException(
                sprintf('Failed to retrieve secret from AWS: %s', $e->getMessage()),
                $e->getStatusCode() ?? 0,
                $e
            );
        }
    }

    public function has(string $key, array $options = []): bool
    {
        [$secretId, $jsonKey] = $this->parseKey($key, $options);

        try {
            // describeSecret is faster/cheaper than getSecretValue if we only want to check existence.
            // But if we are querying a nested JSON key, we still need to verify if the nested key exists.
            if ($jsonKey !== null) {
                return $this->get($key, $options) !== null;
            }

            $this->client->describeSecret([
                'SecretId' => $secretId,
            ]);
            return true;

        } catch (AwsException $e) {
            if ($e->getAwsErrorCode() === 'ResourceNotFoundException') {
                return false;
            }
            throw new SecretProviderException(
                sprintf('Failed to check secret existence in AWS: %s', $e->getMessage()),
                $e->getStatusCode() ?? 0,
                $e
            );
        }
    }

    /**
     * Parse key to check if a nested JSON key is requested.
     * Support formats:
     *   1. "my-secret:my-key"
     *   2. "my-secret" with options ['json_key' => 'my-key'] or ['key' => 'my-key']
     *
     * @return array{0: string, 1: string|null} [SecretId, JsonKey]
     */
    private function parseKey(string $key, array $options): array
    {
        $jsonKey = $options['json_key'] ?? $options['key'] ?? null;

        if (strpos($key, ':') !== false) {
            [$secretId, $delimitedKey] = explode(':', $key, 2);
            return [$secretId, $delimitedKey];
        }

        return [$key, $jsonKey !== null ? (string) $jsonKey : null];
    }
}
