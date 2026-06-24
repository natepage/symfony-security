<?php
declare(strict_types=1);

namespace NatePage\SymfonySecurity\OAuth\User;

use Symfony\Component\Security\Core\User\UserInterface;

interface OAuthUserInterface extends UserInterface
{
    public function getOAuthParams(): array;

    public function setOAuthParams(array $oauthParams): void;
}
