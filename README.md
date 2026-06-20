# Unified Secrets Access for PHP (`scoult/secrets`)

A lightweight, provider-agnostic PHP library to fetch configuration secrets from a variety of sources. Your application logic remains clean and decouples itself from the secret engine (e.g. Microsoft Azure App Configuration, Environment Variables, or Vaults).

---

## Features

- **Provider-agnostic interface** (`SecretsProviderInterface`) so your app logic doesn't care where secrets come from.
- **Out-of-the-box Microsoft Azure App Configuration** provider with HMAC authentication.
- **Azure Key Vault Resolution**: Seamlessly resolves `@Microsoft.KeyVault` secret references inside Azure App Configuration when paired with `AzureKeyVaultResolver`.
- **Environment Variable Provider** with automatic key normalization (e.g., `database.password` mapping to `DATABASE_PASSWORD`).
- **Chain of Responsibility provider** to implement robust lookup fallbacks.
- **Cache Decorator** conforming to PSR-16 (`Psr\SimpleCache\CacheInterface`) to minimize HTTP roundtrips, reduce latency, and lower Azure billing.
- **Modern PHP** design complying with PSR-4, PSR-17, and PSR-18 standards.

---

## Installation

Install the package via Composer:

```bash
composer require scoult/secrets
```

Ensure you have a PSR-18 HTTP client (e.g., Guzzle) installed in your project:

```bash
composer require guzzlehttp/guzzle guzzlehttp/psr7
```

---

## Usage

### 1. Azure App Configuration Provider

This provider connects to Azure App Configuration directly using a standard connection string and uses the REST API authenticated via HMAC-SHA256 signatures.

```php
use Scoult\Secrets\Providers\AzureAppConfigurationProvider;

// Instantiate the provider with your connection string
$connectionString = 'Endpoint=https://your-store.azconfig.io;Id=your-access-key-id;Secret=your-base64-secret';
$provider = new AzureAppConfigurationProvider($connectionString);

// Retrieve a configuration variable
$dbPassword = $provider->get('database.password');
```

#### Specifying Labels
Azure App Configuration allows keys to be tagged with labels. You can target specific labels via the options array:

```php
$prodPassword = $provider->get('database.password', ['label' => 'production']);
```

---

### 2. Auto-resolving Key Vault References

If your Azure App Configuration contains references to Azure Key Vault secrets (e.g., values stored with the content type `application/vnd.microsoft.appconfig.keyvaultref+json`), you can inject `AzureKeyVaultResolver` to automatically fetch and resolve those secrets:

```php
use Scoult\Secrets\Providers\AzureAppConfigurationProvider;
use Scoult\Secrets\Resolvers\AzureKeyVaultResolver;

// Provide a mechanism to supply/retrieve your Entra ID/Bearer Token
$tokenProvider = function () {
    // Return a fresh token (e.g. from Cache, Azure Identity SDK, or OAuth client)
    return 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1d...'; 
};

// Create the resolver
$keyVaultResolver = new AzureKeyVaultResolver($tokenProvider);

// Pass the resolver to the App Configuration provider
$provider = new AzureAppConfigurationProvider(
    $connectionString,
    null, // Auto-discovers Guzzle Client
    null, // Auto-discovers Guzzle Request Factory
    null, // Auto-discovers Guzzle Stream Factory
    $keyVaultResolver
);

// If database.password points to Key Vault, it will automatically dereference and return the secret value
$secretValue = $provider->get('database.password');
```

---

### 3. AWS Secrets Manager Provider

This provider integrates with AWS Secrets Manager. It accepts either an instance of `Aws\SecretsManager\SecretsManagerClient` or a configuration array directly.

```php
use Aws\SecretsManager\SecretsManagerClient;
use Scoult\Secrets\Providers\AwsSecretsManagerProvider;

// 1. Initialize using configuration array
$provider = new AwsSecretsManagerProvider([
    'region' => 'us-west-2',
    'version' => '2017-10-17'
]);

// 2. Fetch standard string secret
$apiKey = $provider->get('my-api-key');

// 3. Fetch from nested JSON secrets
// If 'my-db-secrets' stores a JSON string: {"username": "admin", "password": "xyz"}
// You can retrieve sub-keys using colon syntax or options array:
$dbPassword = $provider->get('my-db-secrets:password');

// Alternatively:
$dbPassword = $provider->get('my-db-secrets', ['key' => 'password']);
```

---

### 4. Combining Providers with `ChainSecretsProvider`

Chain multiple providers together. For example, check local environment variables first, falling back to Azure App Configuration:

```php
use Scoult\Secrets\Providers\ChainSecretsProvider;
use Scoult\Secrets\Providers\EnvSecretsProvider;
use Scoult\Secrets\Providers\AzureAppConfigurationProvider;

$chain = new ChainSecretsProvider([
    new EnvSecretsProvider(), // Checks $_ENV / getenv() first
    new AzureAppConfigurationProvider($connectionString) // Fallback
]);

// If DATABASE_PASSWORD is set in environment, returns that. Otherwise, queries Azure.
$dbPassword = $chain->get('database.password');
```

---

### 5. Performance Optimization via Caching

Repeated HTTP requests to Azure App Configuration on every script execution can impact performance and increase costs. Wrap your provider in `CachedSecretsProvider` using any PSR-16 cache:

```php
use Scoult\Secrets\Providers\AzureAppConfigurationProvider;
use Scoult\Secrets\Providers\CachedSecretsProvider;

$azureProvider = new AzureAppConfigurationProvider($connectionString);

// Wrap the provider in CachedSecretsProvider with your PSR-16 cache instance
// Defaults to 1 hour (3600 seconds) cache TTL.
$provider = new CachedSecretsProvider($azureProvider, $psr16Cache, 3600);

// First call: Makes HTTP request to Azure
$val = $provider->get('my.secret');

// Subsequent calls: Read from cache directly
$val = $provider->get('my.secret');
```

---

## Exception Handling

All provider-specific exceptions inherit from `Scoult\Secrets\Exceptions\SecretProviderException`.

```php
use Scoult\Secrets\Exceptions\SecretProviderException;

try {
    $secret = $provider->get('database.password');
} catch (SecretProviderException $e) {
    // Handle request failure, unauthorized credentials, or connection issues
    error_log("Failed to fetch secret: " . $e->getMessage());
}
```

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
