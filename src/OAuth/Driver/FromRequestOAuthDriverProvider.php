<?php
declare(strict_types=1);

namespace NatePage\SymfonySecurity\OAuth\Driver;

use NatePage\Utils\Helper\StringHelper;
use Psr\Container\ContainerInterface;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Contracts\Service\ResetInterface;

final class FromRequestOAuthDriverProvider implements OAuthDriverProviderInterface, ResetInterface
{
    private ?OAuthDriverInterface $oauthDriver = null;

    public function __construct(
        private readonly RequestStack $requestStack,
        private readonly ContainerInterface $oauthDrivers,
    ) {
    }

    /**
     * @throws \Psr\Container\ContainerExceptionInterface
     * @throws \Psr\Container\NotFoundExceptionInterface
     */
    public function getOAuthDriver(): OAuthDriverInterface
    {
        if ($this->oauthDriver !== null) {
            return $this->oauthDriver;
        }

        $currentRequest = $this->requestStack->getCurrentRequest();
        $driverName = $currentRequest?->attributes->get(self::KEY);

        if (StringHelper::isEmpty($driverName)) {
            throw new \LogicException(sprintf('The "%s" attribute is missing from the request.', self::KEY));
        }

        if ($this->oauthDrivers->has($driverName) === false) {
            throw new \LogicException(sprintf('No OAuth driver found for "%s".', $driverName));
        }

        return $this->oauthDriver = $this->oauthDrivers->get($driverName);
    }

    public function reset(): void
    {
        $this->oauthDriver = null;
    }
}
