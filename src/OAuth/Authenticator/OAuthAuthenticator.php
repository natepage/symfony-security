<?php
declare(strict_types=1);

namespace NatePage\SymfonySecurity\OAuth\Authenticator;

use NatePage\SymfonySecurity\OAuth\Driver\OAuthDriverInterface;
use NatePage\SymfonySecurity\OAuth\Driver\OAuthDriverProviderInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

final class OAuthAuthenticator extends AbstractAuthenticator
{
    public function __construct(
        private readonly OAuthDriverInterface $oauthDriver,
        private readonly LoggerInterface $logger,
    ) {
    }

    public function authenticate(Request $request): Passport
    {
        try {
            $user = $this->oauthDriver->handleCallback($request);
        } catch (\Throwable $throwable) {
            $this->logger->error('OAuth authentication failed', [
                'error' => $throwable->getMessage(),
                'errorClass' => \get_class($throwable),
                'errorFile' => $throwable->getFile(),
                'errorLine' => $throwable->getLine(),
            ]);

            throw new AuthenticationException('OAuth authentication failed', previous: $throwable);
        }

        return new SelfValidatingPassport(new UserBadge($user->getUserIdentifier(), static function () use ($user) {
            return $user;
        }));
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return $this->oauthDriver->handleAuthSuccess($request);
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return $this->oauthDriver->handleAuthFailure($request, $exception);
    }

    public function supports(Request $request): ?bool
    {
        return $this->oauthDriver->supports($request);
    }
}
