<?php
declare(strict_types=1);

namespace NatePage\SymfonySecurity\OAuth\Listener;

use NatePage\SymfonySecurity\OAuth\Driver\OAuthDriverInterface;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Security\Http\Event\LogoutEvent;

#[AsEventListener(LogoutEvent::class)]
final readonly class LogoutListener
{
    public function __construct(private OAuthDriverInterface $driver)
    {
    }

    public function __invoke(LogoutEvent $event): void
    {
        $user = $event->getToken()?->getUser();
        if ($user === null) {
            return;
        }

        $logoutUrl = $this->driver->getLogoutUrl($user);

        $event->setResponse(new RedirectResponse($logoutUrl));
    }
}
