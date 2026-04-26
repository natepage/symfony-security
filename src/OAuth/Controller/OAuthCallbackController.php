<?php
declare(strict_types=1);

namespace NatePage\SymfonySecurity\OAuth\Controller;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

#[Route('/app/oauth/callback', name: self::ROUTE_APP_OAUTH_CALLBACK, methods: ['GET'])]
final class OAuthCallbackController
{
    public const string ROUTE_APP_OAUTH_CALLBACK = 'app_oauth_callback';

    public function __invoke(): Response
    {
        // This is a placeholder as the OAuth authenticator should handle the redirect after callback.
        return new Response('OAuth Callback');
    }
}
