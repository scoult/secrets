<?php

declare(strict_types=1);

namespace Scoult\Secrets\Providers;

use Scoult\Secrets\Contracts\SecretsProviderInterface;
use Scoult\Secrets\Exceptions\SecretProviderException;

/**
 * A composite provider that chains multiple SecretsProviderInterface instances.
 * Lookups are performed in the order providers are registered.
 */
class ChainSecretsProvider implements SecretsProviderInterface
{
    /**
     * @var array<SecretsProviderInterface>
     */
    private array $providers = [];

    /**
     * @param array<SecretsProviderInterface> $providers Initial list of providers.
     */
    public function __construct(array $providers = [])
    {
        foreach ($providers as $provider) {
            $this->addProvider($provider);
        }
    }

    /**
     * Add a provider to the end of the chain.
     */
    public function addProvider(SecretsProviderInterface $provider): self
    {
        $this->providers[] = $provider;
        return $this;
    }

    /**
     * Get the list of registered providers in the chain.
     *
     * @return array<SecretsProviderInterface>
     */
    public function getProviders(): array
    {
        return $this->providers;
    }

    public function get(string $key, array $options = []): ?string
    {
        foreach ($this->providers as $provider) {
            try {
                if ($provider->has($key, $options)) {
                    return $provider->get($key, $options);
                }
            } catch (SecretProviderException $e) {
                // If a provider in the chain fails, we can optionally continue or throw.
                // For safety and robustness, if a chain provider fails, we should check if
                // options specify whether to ignore failures, or we should log/continue.
                // Let's implement a 'ignore_chain_errors' option, defaulting to true to ensure high availability.
                if (!($options['ignore_chain_errors'] ?? true)) {
                    throw $e;
                }
            }
        }

        return null;
    }

    public function has(string $key, array $options = []): bool
    {
        foreach ($this->providers as $provider) {
            try {
                if ($provider->has($key, $options)) {
                    return true;
                }
            } catch (SecretProviderException $e) {
                if (!($options['ignore_chain_errors'] ?? true)) {
                    throw $e;
                }
            }
        }

        return false;
    }
}
