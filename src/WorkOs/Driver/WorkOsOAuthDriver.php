<?php
declare(strict_types=1);

namespace NatePage\SymfonySecurity\WorkOs\Driver;

use NatePage\SymfonySecurity\OAuth\Driver\AbstractOAuthDriver;
use NatePage\SymfonySecurity\OAuth\User\OAuthUserInterface;
use NatePage\SymfonySecurity\OAuth\ValueObject\Invitation;
use NatePage\SymfonySecurity\WorkOs\Event\UserFromWorkOsAuthResponseEvent;
use NatePage\SymfonySecurity\WorkOs\Exception\InvalidStateException;
use NatePage\SymfonySecurity\WorkOs\Exception\InvalidUserException;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use NatePage\Utils\Helper\StringHelper;
use Psr\Log\LoggerInterface;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;
use WorkOS\Resource\AuthenticateResponse;
use WorkOS\Resource\CreateUserInviteOptionsLocale;
use WorkOS\Resource\Invitation as WorkOsInvitation;
use WorkOS\Resource\UserInvite;
use WorkOS\Resource\UserManagementAuthenticationProvider;
use WorkOS\WorkOS;

final class WorkOsOAuthDriver extends AbstractOAuthDriver
{
    private const string CSRF_TOKEN_ID = 'work_os_auth_%s';

    private const int DEFAULT_INVITATION_EXPIRY_IN_DAYS = 5;

    private const string JWK_CACHE_KEY = 'work_os_jwks_%s';

    public function __construct(
        private readonly CacheInterface $cache,
        private readonly CsrfTokenManagerInterface $csrfTokenManager,
        private readonly EventDispatcherInterface $eventDispatcher,
        private readonly LoggerInterface $logger,
        private readonly WorkOS $workOs,
        private readonly string $firewallName,
        private readonly string $clientId,
        private readonly string $logoutRedirectRouteName,
        string $callbackRouteName,
        UrlGeneratorInterface $urlGenerator,
        private readonly Security $security,
        private readonly ?string $organisationId = null,
        private readonly ?string $authProvider = null,
    ) {
        parent::__construct($callbackRouteName, $urlGenerator);
    }

    /**
     * @throws \WorkOS\Exception\ConfigurationException
     */
    public function getAuthorizationUrl(Request $request): string
    {
        $state = [
            // Keep in mind that generateLastUrl() remove query parameters not defined in the route
            self::PARAM_LAST_URL => $this->generateLastUrl($request),
            'token' => $this->csrfTokenManager->getToken($this->getCsrfTokenId())->getValue(),
        ];

        $provider = $this->authProvider
            ? UserManagementAuthenticationProvider::from($this->authProvider)
            : UserManagementAuthenticationProvider::Authkit;

        return $this->workOs->userManagement()->getAuthorizationUrl(
            redirectUri: $this->generateCallbackUrl(),
            provider: $provider,
            state: StringHelper::urlSafeBase64Encode(\json_encode($state)),
            organizationId: $this->organisationId,
        );
    }

    public function getLogoutUrl(UserInterface $user): string
    {
        if ($user instanceof OAuthUserInterface === false) {
            throw new InvalidUserException('User must be an instance of OAuthUserInterface to get logout URL');
        }

        $oauthParams = $user->getOAuthParams();
        if (isset($oauthParams[self::PARAM_SESSION_ID]) === false) {
            throw new InvalidUserException('User is missing session ID in OAuth parameters to get logout URL');
        }

        return $this->workOs->userManagement()->getLogoutUrl(
            $oauthParams[self::PARAM_SESSION_ID],
            $this->generateAbsoluteUrl($this->logoutRedirectRouteName)
        );
    }

    public function handleAuthSuccess(Request $request): RedirectResponse
    {
        $state = $this->decodeState($request->query->get('state'));

        return new RedirectResponse($state[self::PARAM_LAST_URL]);
    }

    /**
     * @throws \WorkOS\Exception\WorkOSException
     */
    public function handleCallback(Request $request): UserInterface
    {
        $code = $request->query->get('code');
        $state = $this->decodeState($request->query->get('state'));

        if ($this->csrfTokenManager->isTokenValid(new CsrfToken($this->getCsrfTokenId(), $state['token'])) === false) {
            throw new InvalidStateException('Invalid state parameter: CSRF token invalid');
        }

        $workOsUser = $this->workOs->userManagement()->authenticateWithCode($code);

        return $this->instantiateUser($workOsUser);
    }

    /**
     * @throws \WorkOS\Exception\WorkOSException
     */
    public function resendInvitation(string $invitationId): Invitation
    {
        $invite = $this->workOs->userManagement()->resendInvitation(
            id: $invitationId,
            locale: CreateUserInviteOptionsLocale::En,
        );

        return $this->instantiateInvitation($invite);
    }

    /**
     * @throws \WorkOS\Exception\WorkOSException
     */
    public function revokeInvitation(string $invitationId): Invitation
    {
        $invite = $this->workOs->userManagement()->revokeInvitation(
            id: $invitationId,
        );

        return $this->instantiateInvitation($invite);
    }

    /**
     * @throws \WorkOS\Exception\WorkOSException
     */
    public function sendInvitation(string $email, ?int $expiryInDays = null): Invitation
    {
        $currentUser = $this->security->getUser();
        $userIdentifier = $currentUser instanceof OAuthUserInterface ? $currentUser->getUserIdentifier() : null;

        $invite = $this->workOs->userManagement()->sendInvitation(
            email: $email,
            organizationId: $this->organisationId,
            expiresInDays: $expiryInDays ?? self::DEFAULT_INVITATION_EXPIRY_IN_DAYS,
            inviterUserId: $userIdentifier,
            locale: CreateUserInviteOptionsLocale::En,
        );

        return $this->instantiateInvitation($invite);
    }

    protected function doRefreshUser(OAuthUserInterface $user): OAuthUserInterface
    {
        $oauthParams = $user->getOAuthParams();

        // If no access token, then fail
        if (isset($oauthParams[self::PARAM_ACCESS_TOKEN], $oauthParams[self::PARAM_REFRESH_TOKEN]) === false) {
            throw new AuthenticationException('No access and/or refresh tokens available for user refresh');
        }

        // If access token is expired, refresh it using the refresh token
        $jwt = $this->decodeAccessToken($oauthParams[self::PARAM_ACCESS_TOKEN]);
        if ($jwt === null) {
            try {
                $workOsUser = $this->workOs->userManagement()->authenticateWithRefreshToken(
                    $oauthParams[self::PARAM_REFRESH_TOKEN]
                );

                return $this->instantiateUser($workOsUser);
            } catch (\Throwable $throwable) {
                $this->logger->debug(\sprintf(
                    'Failed to refresh accessToken during user refresh: %s',
                    $throwable->getMessage()
                ));

                throw new AuthenticationException('Failed to refresh user access token', previous: $throwable);
            }
        }

        return $user;
    }

    private function decodeAccessToken(string $accessToken): ?array
    {
        try {
            return (array)JWT::decode($accessToken, JWK::parseKeySet($this->getJWKs()));
        } catch (\Throwable $throwable) {
            $this->logger->debug(\sprintf('Failed to decode accessToken: %s', $throwable->getMessage()));
        }

        return null;
    }

    private function decodeState(?string $state): array
    {
        if (StringHelper::isEmpty($state)) {
            throw new InvalidStateException('Invalid state parameter: no state provided');
        }

        $data = StringHelper::urlSafeBase64Decode($state);

        if (\json_validate($data) === false) {
            throw new InvalidStateException('Invalid state parameter: invalid data');
        }

       return \json_decode($data, true);
    }

    private function getCsrfTokenId(): string
    {
        return \sprintf(self::CSRF_TOKEN_ID, $this->clientId);
    }

    /**
     * @throws \Psr\Cache\InvalidArgumentException
     */
    private function getJWKs(): array
    {
        $jwkCacheKey = \sprintf(self::JWK_CACHE_KEY, $this->clientId);

        return $this->cache->get($jwkCacheKey, function (ItemInterface $item): array {
            $item->expiresAfter(3600);

            return $this->workOs->userManagement()->getJwks($this->clientId)->toArray();
        });
    }

    private function instantiateInvitation(UserInvite|WorkOsInvitation $invite): Invitation
    {
        return new Invitation(
            id: $invite->id,
            status: $invite->state->value,
            token: $invite->token,
            expiresAt: $invite->expiresAt,
            createdAt: $invite->createdAt,
        );
    }

    private function instantiateUser(AuthenticateResponse $response): OAuthUserInterface
    {
        $jwt = $this->decodeAccessToken($response->accessToken);
        $event = new UserFromWorkOsAuthResponseEvent($this->firewallName, $response, $jwt);

        $this->eventDispatcher->dispatch($event);

        $user = $event->getOAuthUser();
        if ($user instanceof OAuthUserInterface === false) {
            throw new InvalidUserException(
                'Event UserFromWorkOsAuthResponseEvent did not return an instance of OAuthUserInterface'
            );
        }

        // Handle impersonation
        if ($response->impersonator !== null) {
            $user->setImpersonator($response->impersonator->email);
        }

        // Set default OAuth params here so applications don't have to do it over and over
        $oauthParams = $user->getOAuthParams();
        $oauthParams[self::PARAM_ACCESS_TOKEN] = $response->accessToken;
        $oauthParams[self::PARAM_REFRESH_TOKEN] = $response->refreshToken;
        $oauthParams[self::PARAM_SESSION_ID] = $jwt['sid'] ?? null;

        $user->setOAuthParams($oauthParams);

        return $user;
    }
}
