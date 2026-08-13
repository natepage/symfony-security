<?php
declare(strict_types=1);

namespace NatePage\SymfonySecurity\OAuth\Authenticator;

use NatePage\SymfonySecurity\OAuth\Driver\OAuthDriverInterface;
use NatePage\SymfonySecurity\OAuth\Event\OAuthAuthenticationFailureEvent;
use NatePage\SymfonySecurity\OAuth\Event\OAuthAuthenticationSuccessEvent;
use NatePage\SymfonySecurity\OAuth\Event\OAuthEntrypointStartForTurboFrameEvent;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

final class OAuthAuthenticator extends AbstractAuthenticator implements AuthenticationEntryPointInterface
{
    public function __construct(
        private readonly OAuthDriverInterface $oauthDriver,
        private readonly LoggerInterface $logger,
        private readonly EventDispatcherInterface $eventDispatcher,
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
        $event = new OAuthAuthenticationSuccessEvent($request, $token, $firewallName);
        $this->eventDispatcher->dispatch($event);

        if ($event->getResponse() !== null) {
            return $event->getResponse();
        }

        return $this->oauthDriver->handleAuthSuccess($request);
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $event = new OAuthAuthenticationFailureEvent($request, $exception);
        $this->eventDispatcher->dispatch($event);

        if ($event->getResponse() !== null) {
            return $event->getResponse();
        }

        return $this->oauthDriver->handleAuthFailure($request, $exception);
    }

    public function supports(Request $request): ?bool
    {
        return $this->oauthDriver->supports($request);
    }

    public function start(Request $request, ?AuthenticationException $authException = null): Response
    {
        $authorizationUrl = $this->oauthDriver->getAuthorizationUrl($request);

        if ($request->headers->has('Turbo-Frame')) {
            $event = new OAuthEntrypointStartForTurboFrameEvent($authorizationUrl, $request->headers->get('Turbo-Frame'));
            $this->eventDispatcher->dispatch($event);

            if ($event->getResponse() !== null) {
                return $event->getResponse();
            }
        }

        return new RedirectResponse($authorizationUrl);
    }
}
