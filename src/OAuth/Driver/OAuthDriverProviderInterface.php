<?php
declare(strict_types=1);

namespace NatePage\SymfonySecurity\OAuth\Driver;

interface OAuthDriverProviderInterface
{
    public const string KEY = 'natepage.oauth.driver';

    public function getOAuthDriver(): OAuthDriverInterface;
}
