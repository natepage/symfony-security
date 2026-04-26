<?php
declare(strict_types=1);

namespace NatePage\SymfonySecurity\OAuth\Entrypoint;

use NatePage\SymfonySecurity\OAuth\Driver\OAuthDriverInterface;
use NatePage\SymfonySecurity\OAuth\Event\OAuthEntrypointStartForTurboFrameEvent;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

final readonly class OAuthEntrypoint implements AuthenticationEntryPointInterface
{
    public function __construct(
        private OAuthDriverInterface $driver,
        private EventDispatcherInterface $eventDispatcher,
    ) {
    }

    public function start(Request $request, ?AuthenticationException $authException = null): Response
    {
        $authorizationUrl = $this->driver->getAuthorizationUrl($request);

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
