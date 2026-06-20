<?php

declare(strict_types=1);

namespace Scoult\Secrets\Providers;

use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Scoult\Secrets\Contracts\SecretResolverInterface;
use Scoult\Secrets\Contracts\SecretsProviderInterface;
use Scoult\Secrets\Exceptions\SecretProviderException;

/**
 * Secrets provider integrating with Microsoft Azure App Configuration REST API using HMAC authentication.
 */
class AzureAppConfigurationProvider implements SecretsProviderInterface
{
    private string $endpoint;
    private string $credentialId;
    private string $credentialSecret;
    private ClientInterface $httpClient;
    private RequestFactoryInterface $requestFactory;
    private StreamFactoryInterface $streamFactory;
    private ?SecretResolverInterface $keyVaultResolver;

    /**
     * @param string $connectionString Connection string from the Azure App Configuration access keys.
     * @param ClientInterface|null $httpClient Custom PSR-18 HTTP client (auto-detected if null).
     * @param RequestFactoryInterface|null $requestFactory Custom PSR-17 Request factory (auto-detected if null).
     * @param StreamFactoryInterface|null $streamFactory Custom PSR-17 Stream factory (auto-detected if null).
     * @param SecretResolverInterface|null $keyVaultResolver Optional resolver for Azure Key Vault references.
     *
     * @throws SecretProviderException if the connection string is invalid or auto-detection fails.
     */
    public function __construct(
        string $connectionString,
        ?ClientInterface $httpClient = null,
        ?RequestFactoryInterface $requestFactory = null,
        ?StreamFactoryInterface $streamFactory = null,
        ?SecretResolverInterface $keyVaultResolver = null
    ) {
        $credentials = $this->parseConnectionString($connectionString);
        $this->endpoint = rtrim($credentials['endpoint'], '/');
        $this->credentialId = $credentials['id'];
        $this->credentialSecret = $credentials['secret'];

        $this->httpClient = $httpClient ?? $this->discoverHttpClient();
        $this->requestFactory = $requestFactory ?? $this->discoverRequestFactory();
        $this->streamFactory = $streamFactory ?? $this->discoverStreamFactory();
        $this->keyVaultResolver = $keyVaultResolver;
    }

    public function get(string $key, array $options = []): ?string
    {
        $response = $this->sendRequest('GET', $key, $options);

        if ($response === null) {
            return null;
        }

        $contentType = $response['content_type'] ?? '';
        $value = $response['value'] ?? null;

        if ($value !== null && $this->isKeyVaultReference($contentType)) {
            if ($this->keyVaultResolver !== null) {
                return $this->keyVaultResolver->resolve($value);
            }
        }

        return $value;
    }

    public function has(string $key, array $options = []): bool
    {
        // Azure App Configuration supports HEAD requests for checking existence.
        // But for HMAC authentication, HEAD request string-to-sign is slightly different.
        // To be safe and reuse the same path, we can perform a GET request.
        // We need the body/content_type metadata anyway to know if it's
        // a Key Vault reference that might resolve to null or present.
        return $this->sendRequest('GET', $key, $options) !== null;
    }

    /**
     * Send an authenticated HTTP request to the App Configuration API.
     *
     * @return array<string, mixed>|null The parsed JSON response, or null if 404.
     *
     * @throws SecretProviderException
     */
    private function sendRequest(string $method, string $key, array $options): ?array
    {
        $host = parse_url($this->endpoint, PHP_URL_HOST);
        if (!$host) {
            throw new SecretProviderException(sprintf('Invalid Azure App Configuration endpoint: %s', $this->endpoint));
        }

        // Build request URI
        // Keys can contain characters like '/' which must be URL encoded.
        $encodedKey = rawurlencode($key);
        $path = '/kv/' . $encodedKey;
        $query = $this->buildQuery($options);
        $uriString = $this->endpoint . $path . ($query !== '' ? '?' . $query : '');

        try {
            $request = $this->requestFactory->createRequest($method, $uriString);

            // Compute HMAC Signatures and Headers
            $date = gmdate('D, d M Y H:i:s \G\M\T');
            $contentHash = base64_encode(hash('sha256', '', true));

            $pathAndQuery = $path . ($query !== '' ? '?' . $query : '');
            $stringToSign = implode("\n", [
                strtoupper($method),
                $pathAndQuery,
                $date . ';' . $host . ';' . $contentHash
            ]);

            $decodedSecret = base64_decode($this->credentialSecret);
            if ($decodedSecret === false) {
                throw new SecretProviderException('Failed to base64-decode Azure App Configuration credential secret.');
            }

            $signature = base64_encode(hash_hmac('sha256', $stringToSign, $decodedSecret, true));

            $authHeader = sprintf(
                'HMAC-SHA256 Credential=%s&SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature=%s',
                $this->credentialId,
                $signature
            );

            // Add headers
            $request = $request
                ->withHeader('Host', $host)
                ->withHeader('x-ms-date', $date)
                ->withHeader('x-ms-content-sha256', $contentHash)
                ->withHeader('Authorization', $authHeader)
                ->withHeader('Accept', 'application/json');

            $response = $this->httpClient->sendRequest($request);
            $statusCode = $response->getStatusCode();

            if ($statusCode === 200) {
                $body = (string) $response->getBody();
                $data = json_decode($body, true);
                if (json_last_error() !== JSON_ERROR_NONE) {
                    throw new SecretProviderException(sprintf('Failed to parse JSON response from Azure: %s', json_last_error_msg()));
                }
                return $data;
            }

            if ($statusCode === 404) {
                return null;
            }

            throw new SecretProviderException(
                sprintf('Azure App Configuration request failed with status code %d. Response: %s', $statusCode, (string) $response->getBody()),
                $statusCode
            );

        } catch (ClientExceptionInterface $e) {
            throw new SecretProviderException(sprintf('HTTP request failed: %s', $e->getMessage()), $e->getCode(), $e);
        }
    }

    private function buildQuery(array $options): string
    {
        $params = [];

        // Check for specific labels
        if (isset($options['label']) && $options['label'] !== '') {
            $params['label'] = $options['label'];
        }

        $params['api-version'] = $options['api-version'] ?? '1.0';

        return http_build_query($params);
    }

    private function isKeyVaultReference(string $contentType): bool
    {
        return str_starts_with($contentType, 'application/vnd.microsoft.appconfig.keyvaultref');
    }

    /**
     * Parse Azure App Configuration Connection String.
     * Format: Endpoint=https://<name>.azconfig.io;Id=<id>;Secret=<secret>
     *
     * @return array<string, string>
     * @throws SecretProviderException
     */
    private function parseConnectionString(string $connectionString): array
    {
        $parts = [];
        foreach (explode(';', $connectionString) as $part) {
            $part = trim($part);
            if ($part === '') {
                continue;
            }
            $pos = strpos($part, '=');
            if ($pos === false) {
                continue;
            }
            $key = strtolower(trim(substr($part, 0, $pos)));
            $value = trim(substr($part, $pos + 1));
            $parts[$key] = $value;
        }

        if (!isset($parts['endpoint'], $parts['id'], $parts['secret'])) {
            throw new SecretProviderException('Invalid connection string. Must contain Endpoint, Id, and Secret.');
        }

        return $parts;
    }

    private function discoverHttpClient(): ClientInterface
    {
        if (class_exists(\GuzzleHttp\Client::class)) {
            return new \GuzzleHttp\Client();
        }
        throw new SecretProviderException(
            'No PSR-18 HTTP client found. Please install guzzlehttp/guzzle or pass a client to the constructor.'
        );
    }

    private function discoverRequestFactory(): RequestFactoryInterface
    {
        if (class_exists(\GuzzleHttp\Psr7\HttpFactory::class)) {
            return new \GuzzleHttp\Psr7\HttpFactory();
        }
        throw new SecretProviderException(
            'No PSR-17 Request Factory found. Please install guzzlehttp/psr7 or pass a factory to the constructor.'
        );
    }

    private function discoverStreamFactory(): StreamFactoryInterface
    {
        if (class_exists(\GuzzleHttp\Psr7\HttpFactory::class)) {
            return new \GuzzleHttp\Psr7\HttpFactory();
        }
        throw new SecretProviderException(
            'No PSR-17 Stream Factory found. Please install guzzlehttp/psr7 or pass a factory to the constructor.'
        );
    }
}
