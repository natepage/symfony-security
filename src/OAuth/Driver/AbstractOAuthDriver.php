<?php
declare(strict_types=1);

namespace NatePage\SymfonySecurity\OAuth\Driver;

use NatePage\SymfonySecurity\OAuth\Controller\OAuthCallbackController;
use NatePage\SymfonySecurity\OAuth\User\OAuthUserInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;

abstract class AbstractOAuthDriver implements OAuthDriverInterface
{
    public function __construct(
        private readonly UrlGeneratorInterface $urlGenerator,
    ) {
    }

    public function handleAuthFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return null;
    }

    public function refreshUser(UserInterface $user): UserInterface
    {
        return $user instanceof OAuthUserInterface === false ? $user : $this->doRefreshUser($user);
    }

    public function supports(Request $request): bool
    {
        return $request->attributes->get('_route') === OAuthCallbackController::ROUTE_APP_OAUTH_CALLBACK;
    }

    abstract protected function doRefreshUser(OAuthUserInterface $user): OAuthUserInterface;

    protected function generateAbsoluteUrl(string $routeName, ?array $routeParams = null): string
    {
        return $this->urlGenerator->generate(
            name: $routeName,
            parameters: $routeParams ?? [],
            referenceType: UrlGeneratorInterface::ABSOLUTE_URL
        );
    }

    protected function generateCallbackUrl(?array $params = null): string
    {
        return $this->generateAbsoluteUrl(OAuthCallbackController::ROUTE_APP_OAUTH_CALLBACK, $params);
    }

    protected function generateLastUrl(Request $request): string
    {
        return $this->generateAbsoluteUrl(
            $request->attributes->get('_route'),
            $request->attributes->get('_route_params')
        );
    }
}
