<?php
declare(strict_types=1);

namespace NatePage\SymfonySecurity\OAuth\User;

trait OAuthUserTrait
{
    protected ?array $oauthParams = null;

    public function getOAuthParams(): array
    {
        return $this->oauthParams ?? [];
    }

    public function setOAuthParams(array $oauthParams): void
    {
        $this->oauthParams = $oauthParams;
    }
}
