<?php
declare(strict_types=1);

namespace NatePage\SymfonySecurity\OAuth\Listener;

use NatePage\SymfonySecurity\OAuth\Driver\OAuthDriverInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Security\Http\Event\LogoutEvent;

final readonly class OAuthLogoutListener
{
    public function __construct(private OAuthDriverInterface $oauthDriver)
    {
    }

    public function __invoke(LogoutEvent $event): void
    {
        $user = $event->getToken()?->getUser();
        if ($user === null) {
            return;
        }

        $logoutUrl = $this->oauthDriver->getLogoutUrl($user);

        $event->setResponse(new RedirectResponse($logoutUrl));
    }
}
