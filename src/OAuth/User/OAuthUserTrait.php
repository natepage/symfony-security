<?php
declare(strict_types=1);

namespace NatePage\SymfonySecurity\OAuth\User;

trait OAuthUserTrait
{
    protected ?string $impersonator = null;

    protected ?array $oauthParams = null;

    public function getImpersonator(): ?string
    {
        return $this->impersonator;
    }

    public function getOAuthParams(): array
    {
        return $this->oauthParams ?? [];
    }

    public function isImpersonated(): bool
    {
        return $this->impersonator !== null;
    }

    public function setOAuthParams(array $oauthParams): void
    {
        $this->oauthParams = $oauthParams;
    }

    public function setImpersonator(string $impersonator): void
    {
        $this->impersonator = $impersonator;
    }
}
