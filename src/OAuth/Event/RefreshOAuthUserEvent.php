<?php
declare(strict_types=1);

namespace NatePage\SymfonySecurity\OAuth\Event;

use NatePage\SymfonySecurity\OAuth\User\OAuthUserInterface;

final class RefreshOAuthUserEvent
{
    public function __construct(
        private OAuthUserInterface $user,
    ) {
    }

    public function getUser(): OAuthUserInterface
    {
        return $this->user;
    }

    public function setUser(OAuthUserInterface $user): void
    {
        $this->user = $user;
    }
}
