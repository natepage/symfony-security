<?php
declare(strict_types=1);

namespace NatePage\SymfonySecurity\OAuth\Controller;

use Symfony\Component\HttpFoundation\Response;

final class OAuthCallbackController
{
    public function __invoke(): Response
    {
        // This is a placeholder as the OAuth authenticator should handle the redirect after callback.
        return new Response('OAuth Callback');
    }
}
