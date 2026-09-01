<?php
declare(strict_types=1);

namespace NatePage\SymfonySecurity\OAuth\User;

use Symfony\Component\Security\Core\User\UserInterface;

interface OAuthUserInterface extends UserInterface
{
    public function getImpersonator(): ?string;

    public function getOAuthParams(): array;

    public function isImpersonated(): bool;

    public function setOAuthParams(array $oauthParams): void;

    public function setImpersonator(?string $impersonator): void;
}
