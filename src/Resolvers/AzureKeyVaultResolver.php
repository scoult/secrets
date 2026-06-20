<?php

declare(strict_types=1);

namespace Scoult\Secrets\Resolvers;

use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Scoult\Secrets\Contracts\SecretResolverInterface;
use Scoult\Secrets\Exceptions\SecretProviderException;

/**
 * Resolves Azure Key Vault references using the Key Vault REST API.
 */
class AzureKeyVaultResolver implements SecretResolverInterface
{
    private ClientInterface $httpClient;
    private RequestFactoryInterface $requestFactory;
    /** @var callable|string */
    private $tokenProvider;
    private string $apiVersion;

    /**
     * @param string|callable $tokenProvider Static token string or callable that returns a valid bearer token.
     * @param ClientInterface|null $httpClient Custom PSR-18 client (auto-detected if null).
     * @param RequestFactoryInterface|null $requestFactory Custom PSR-17 Request factory (auto-detected if null).
     * @param string $apiVersion Key Vault API version (default 7.4).
     */
    public function __construct(
        $tokenProvider,
        ?ClientInterface $httpClient = null,
        ?RequestFactoryInterface $requestFactory = null,
        string $apiVersion = '7.4'
    ) {
        $this->tokenProvider = $tokenProvider;
        $this->apiVersion = $apiVersion;

        $this->httpClient = $httpClient ?? $this->discoverHttpClient();
        $this->requestFactory = $requestFactory ?? $this->discoverRequestFactory();
    }

    public function resolve(string $reference): ?string
    {
        // Reference is expected to be a JSON string like:
        // {"uri":"https://<keyvault-name>.vault.azure.net/secrets/<secret-name>/<secret-version>"}
        $data = json_decode($reference, true);
        if (json_last_error() !== JSON_ERROR_NONE || !isset($data['uri'])) {
            return null;
        }

        $uri = $data['uri'];

        // Append api-version query parameter
        $separator = strpos($uri, '?') === false ? '?' : '&';
        $uriWithVersion = $uri . $separator . 'api-version=' . $this->apiVersion;

        $token = $this->getBearerToken();

        try {
            $request = $this->requestFactory->createRequest('GET', $uriWithVersion)
                ->withHeader('Authorization', 'Bearer ' . $token)
                ->withHeader('Accept', 'application/json');

            $response = $this->httpClient->sendRequest($request);
            $statusCode = $response->getStatusCode();

            if ($statusCode === 200) {
                $body = (string) $response->getBody();
                $secretData = json_decode($body, true);
                if (json_last_error() !== JSON_ERROR_NONE) {
                    throw new SecretProviderException(sprintf('Failed to parse Key Vault JSON response: %s', json_last_error_msg()));
                }
                return $secretData['value'] ?? null;
            }

            if ($statusCode === 404) {
                return null;
            }

            throw new SecretProviderException(
                sprintf('Key Vault request failed with status code %d. Response: %s', $statusCode, (string) $response->getBody()),
                $statusCode
            );

        } catch (ClientExceptionInterface $e) {
            throw new SecretProviderException(sprintf('Key Vault HTTP request failed: %s', $e->getMessage()), $e->getCode(), $e);
        }
    }

    private function getBearerToken(): string
    {
        if (is_callable($this->tokenProvider)) {
            return (string) ($this->tokenProvider)();
        }

        return (string) $this->tokenProvider;
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
}
