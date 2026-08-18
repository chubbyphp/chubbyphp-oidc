<?php

declare(strict_types=1);

namespace Chubbyphp\Tests\Oidc;

use GuzzleHttp\Client as HttpClient;
use PHPUnit\Event\TestRunner\ExecutionStarted;
use PHPUnit\Event\TestRunner\ExecutionStartedSubscriber;
use PHPUnit\Runner\Extension\Extension;
use PHPUnit\Runner\Extension\Facade;
use PHPUnit\Runner\Extension\ParameterCollection;
use PHPUnit\TextUI\Configuration\Configuration;
use Testcontainers\Container\GenericContainer;
use Testcontainers\Container\StartedGenericContainer;
use Testcontainers\ContainerClient\DockerContainerClient;

/**
 * Starts a mock-oauth2-server before the first integration test and stops it after the last one, unless
 * MOCK_OAUTH2_SERVER_URL points to a running one already. The integration tests themselves only use the resolved
 * MOCK_OAUTH2_SERVER_URL and get skipped if there is none (no docker compatible daemon).
 *
 * Registered by phpunit.integration.xml only: within phpunit.xml it would run for every unit test process as well,
 * infection alone runs one of those per mutant.
 *
 * @internal
 */
final class MockOAuth2ServerExtension implements ExecutionStartedSubscriber, Extension
{
    public const string ENV_MOCK_OAUTH2_SERVER_URL = 'MOCK_OAUTH2_SERVER_URL';

    private const string IMAGE = 'ghcr.io/navikt/mock-oauth2-server:6.0.0';
    private const int PORT = 8080;
    private const string READY_PATH = '/default/.well-known/openid-configuration';
    private const int READY_TIMEOUT = 120;

    private ?StartedGenericContainer $startedContainer = null;

    public function __destruct()
    {
        $this->startedContainer?->stop();
    }

    public function bootstrap(
        Configuration $configuration,
        Facade $facade,
        ParameterCollection $parameters
    ): void {
        $facade->registerSubscriber($this);
    }

    public function notify(ExecutionStarted $event): void
    {
        if (null !== $this->startedContainer) {
            return;
        }

        $serverUrl = getenv(self::ENV_MOCK_OAUTH2_SERVER_URL) ?: 'http://localhost:'.self::PORT;

        if (self::isReachable($serverUrl)) {
            putenv(self::ENV_MOCK_OAUTH2_SERVER_URL.'='.$serverUrl);

            return;
        }

        // there is no reachable mock-oauth2-server (yet), the integration tests skip if it stays that way
        putenv(self::ENV_MOCK_OAUTH2_SERVER_URL);

        if (!self::isDockerAvailable()) {
            return;
        }

        putenv(self::ENV_MOCK_OAUTH2_SERVER_URL.'='.$this->startMockOAuth2Server());
    }

    private function startMockOAuth2Server(): string
    {
        $networkName = self::resolveOwnNetworkName();

        if (null !== $networkName) {
            // the tests run within a container themselves (a ci step using a docker image): the mock-oauth2-server
            // joins its docker network and is used through its container ip, a published port would be published
            // on the docker host, which is not reachable from within that network
            $this->startedContainer = (new GenericContainer(self::IMAGE))->withNetwork($networkName)->start();

            $url = \sprintf('http://%s:%d', $this->startedContainer->getIpAddress($networkName), self::PORT);
        } else {
            // the tests run on the docker host: the mock-oauth2-server is used through its published port
            $this->startedContainer = (new GenericContainer(self::IMAGE))->withExposedPorts(self::PORT)->start();

            $url = \sprintf(
                'http://%s:%d',
                $this->startedContainer->getHost(),
                $this->startedContainer->getMappedPort(self::PORT)
            );
        }

        $this->waitUntilReachable($url);

        return $url;
    }

    private function waitUntilReachable(string $url): void
    {
        $timeout = microtime(true) + self::READY_TIMEOUT;

        do {
            if (self::isReachable($url)) {
                return;
            }

            usleep(500000);
        } while (microtime(true) < $timeout);

        throw new \RuntimeException(\sprintf(
            "The mock oauth2 server at \"%s\" was not reachable within %d seconds, container logs:\n%s",
            $url,
            self::READY_TIMEOUT,
            $this->startedContainer?->logs()
        ));
    }

    private static function isReachable(string $url): bool
    {
        try {
            $response = (new HttpClient(['timeout' => 2, 'connect_timeout' => 1]))->get($url.self::READY_PATH);

            return 200 === $response->getStatusCode();
        } catch (\Throwable) {
            return false;
        }
    }

    private static function isDockerAvailable(): bool
    {
        $dockerHost = getenv('DOCKER_HOST') ?: 'unix:///var/run/docker.sock';

        if (str_starts_with($dockerHost, 'unix://')) {
            return file_exists(substr($dockerHost, 7));
        }

        /** @var array{host?: string, port?: int} $parts */
        $parts = parse_url($dockerHost) ?: [];

        $connection = @fsockopen($parts['host'] ?? 'localhost', $parts['port'] ?? 2375, $errno, $errstr, 1.0);

        if (!\is_resource($connection)) {
            return false;
        }

        fclose($connection);

        return true;
    }

    /**
     * The name of a docker network the current process (container) is attached to, null if the tests do not run
     * within a container or if there is no network to share.
     */
    private static function resolveOwnNetworkName(): ?string
    {
        $containerId = self::resolveOwnContainerId();

        if (null === $containerId) {
            return null;
        }

        try {
            $networks = (array) DockerContainerClient::getDockerClient()
                ->containerInspect($containerId)
                ?->getNetworkSettings()
                ?->getNetworks()
            ;
        } catch (\Throwable) {
            return null;
        }

        foreach (array_keys($networks) as $networkName) {
            // "host" shares the network namespace with the docker host, so the published port is reachable
            if (\in_array($networkName, ['host', 'none'], true)) {
                return null;
            }

            return (string) $networkName;
        }

        return null;
    }

    private static function resolveOwnContainerId(): ?string
    {
        if (!file_exists('/.dockerenv')) {
            return null;
        }

        $mountInfo = @file_get_contents('/proc/self/mountinfo');

        // docker mounts /var/lib/docker/containers/<id>/{hostname,hosts,resolv.conf} into its containers
        if (false !== $mountInfo && 1 === preg_match('#/containers/([0-9a-f]{64})/#', $mountInfo, $matches)) {
            return $matches[1];
        }

        // fallback: without an explicit hostname docker uses the short container id
        $hostname = gethostname();

        return false !== $hostname && '' !== $hostname ? $hostname : null;
    }
}
