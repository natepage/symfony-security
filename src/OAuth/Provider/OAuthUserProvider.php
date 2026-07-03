<?php
declare(strict_types=1);

namespace NatePage\SymfonySecurity\OAuth\Provider;

use NatePage\SymfonySecurity\OAuth\Driver\OAuthDriverInterface;
use NatePage\SymfonySecurity\OAuth\Event\RefreshOAuthUserEvent;
use NatePage\SymfonySecurity\OAuth\User\OAuthUserInterface;
use RuntimeException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

final readonly class OAuthUserProvider implements UserProviderInterface
{
    public function __construct(
        private EventDispatcherInterface $eventDispatcher,
        private OAuthDriverInterface $oauthDriver,
        private string $userClass,
    ) {
    }

    public function loadUserByIdentifier(string $identifier): UserInterface
    {
        throw new RuntimeException(\sprintf('%s not implemented', __FUNCTION__));
    }

    public function refreshUser(UserInterface $user): UserInterface
    {
        $user = $this->oauthDriver->refreshUser($user);
        if ($user instanceof OAuthUserInterface === false) {
            return $user;
        }

        $event = new RefreshOAuthUserEvent($user);

        // Extension point for application to persist user in their system, etc.
        $this->eventDispatcher->dispatch($event);

        return $event->getUser();
    }

    public function supportsClass(string $class): bool
    {
        return \is_a($class, $this->userClass, true);
    }
}
