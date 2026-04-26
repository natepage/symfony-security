<?php
declare(strict_types=1);

namespace NatePage\SymfonySecurity\Bundle\Enum;

enum ConfigTag: string
{
    case OAuthDriver = 'symfony_security.oauth.driver';
}
