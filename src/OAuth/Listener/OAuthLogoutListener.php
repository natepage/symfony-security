<?php
declare(strict_types=1);

namespace NatePage\SymfonySecurity\OAuth\Listener;

use NatePage\SymfonySecurity\OAuth\Driver\OAuthDriverProviderInterface;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Security\Http\Event\LogoutEvent;

#[AsEventListener(LogoutEvent::class)]
final readonly class OAuthLogoutListener
{
    public function __construct(private OAuthDriverProviderInterface $oauthDriverProvider)
    {
    }

    public function __invoke(LogoutEvent $event): void
    {
        $user = $event->getToken()?->getUser();
        if ($user === null) {
            return;
        }

        $logoutUrl = $this->oauthDriverProvider->getOAuthDriver()->getLogoutUrl($user);

        $event->setResponse(new RedirectResponse($logoutUrl));
    }
}
