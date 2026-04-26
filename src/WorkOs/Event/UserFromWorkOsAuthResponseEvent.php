<?php
declare(strict_types=1);

namespace NatePage\SymfonySecurity\WorkOs\Event;

use NatePage\SymfonySecurity\OAuth\User\OAuthUserInterface;
use WorkOS\Resource\AuthenticateResponse;

final class UserFromWorkOsAuthResponseEvent
{
    private ?OAuthUserInterface $oauthUser = null;

    public function __construct(
        private readonly AuthenticateResponse $authResponse,
        private readonly ?array $decodedAccessToken = null,
    ) {
    }

    public function getAuthResponse(): AuthenticateResponse
    {
        return $this->authResponse;
    }

    public function getDecodedAccessToken(): ?array
    {
        return $this->decodedAccessToken;
    }

    public function getOAuthUser(): ?OAuthUserInterface
    {
        return $this->oauthUser;
    }

    public function setOAuthUser(?OAuthUserInterface $oauthUser): void
    {
        $this->oauthUser = $oauthUser;
    }
}
