<?php
declare(strict_types=1);

namespace NatePage\SymfonySecurity\OAuth\Driver;

use NatePage\SymfonySecurity\OAuth\ValueObject\Invitation;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;

interface OAuthDriverInterface
{
    public const string PARAM_ACCESS_TOKEN = 'accessToken';

    public const string PARAM_LAST_URL = 'lastUrl';

    public const string PARAM_REFRESH_TOKEN = 'refreshToken';

    public const string PARAM_SESSION_ID = 'sessionId';

    public function getAuthorizationUrl(Request $request): string;

    public function getLogoutUrl(UserInterface $user): string;

    public function handleAuthSuccess(Request $request): RedirectResponse;

    public function handleAuthFailure(Request $request, AuthenticationException $exception): ?Response;

    public function handleCallback(Request $request): UserInterface;

    public function refreshUser(UserInterface $user): UserInterface;

    public function resendInvitation(string $invitationId): Invitation;

    public function revokeInvitation(string $invitationId): Invitation;

    public function sendInvitation(string $email, ?int $expiryInDays = null): Invitation;

    public function supports(Request $request): bool;
}
