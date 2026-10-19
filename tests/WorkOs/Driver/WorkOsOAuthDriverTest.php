<?php
declare(strict_types=1);

namespace NatePage\SymfonySecurity\Tests\WorkOs\Driver;

use DateTimeImmutable;
use NatePage\SymfonySecurity\OAuth\Driver\OAuthDriverInterface;
use NatePage\SymfonySecurity\OAuth\User\OAuthUserInterface;
use NatePage\SymfonySecurity\OAuth\User\OAuthUserTrait;
use NatePage\SymfonySecurity\WorkOs\Driver\WorkOsOAuthDriver;
use NatePage\SymfonySecurity\WorkOs\Event\UserFromWorkOsAuthResponseEvent;
use NatePage\SymfonySecurity\WorkOs\Exception\InvalidOrganisationException;
use NatePage\Utils\Helper\StringHelper;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;
use WorkOS\Resource\AuthenticateResponse;
use WorkOS\Resource\User;
use WorkOS\Service\UserManagement;
use WorkOS\WorkOS;

final class WorkOsOAuthDriverTest extends TestCase
{
    private const string ORGANISATION_ID = 'org_tenancy';

    /**
     * @return iterable<string, array{string|null, string|null}>
     */
    public static function provideAcceptedOrganisations(): iterable
    {
        yield 'configured organisation, response for it' => [self::ORGANISATION_ID, self::ORGANISATION_ID];
        yield 'no configured organisation, response without organisation' => [null, null];
        yield 'no configured organisation, response for any organisation' => [null, 'org_other'];
    }

    /**
     * @return iterable<string, array{string|null, string}>
     */
    public static function provideRejectedOrganisations(): iterable
    {
        yield 'response for another organisation' => ['org_other', 'Expected organisation org_tenancy, got org_other'];
        yield 'response without organisation' => [null, 'Expected organisation org_tenancy, got none'];
    }

    #[DataProvider('provideAcceptedOrganisations')]
    public function testHandleCallbackAcceptsOrganisation(?string $configured, ?string $responded): void
    {
        $user = $this->createUser();
        $dispatcher = $this->createMock(EventDispatcherInterface::class);
        $dispatcher
            ->expects($this->once())
            ->method('dispatch')
            ->willReturnCallback(static function (UserFromWorkOsAuthResponseEvent $event) use ($user): object {
                $event->setOAuthUser($user);

                return $event;
            });

        $userManagement = $this->createStub(UserManagement::class);
        $userManagement->method('authenticateWithCode')
            ->willReturn($this->createResponse($responded));

        $driver = $this->createDriver($configured, $userManagement, $dispatcher);

        self::assertSame($user, $driver->handleCallback($this->createCallbackRequest()));
    }

    #[DataProvider('provideRejectedOrganisations')]
    public function testHandleCallbackRejectsOrganisation(?string $responded, string $message): void
    {
        $dispatcher = $this->createMock(EventDispatcherInterface::class);
        $dispatcher->expects($this->never())
            ->method('dispatch');

        $userManagement = $this->createStub(UserManagement::class);
        $userManagement->method('authenticateWithCode')
            ->willReturn($this->createResponse($responded));

        $driver = $this->createDriver(self::ORGANISATION_ID, $userManagement, $dispatcher);

        $this->expectException(InvalidOrganisationException::class);
        $this->expectExceptionMessage($message);

        $driver->handleCallback($this->createCallbackRequest());
    }

    public function testRefreshUserRejectsOtherOrganisation(): void
    {
        $dispatcher = $this->createMock(EventDispatcherInterface::class);
        $dispatcher->expects($this->never())
            ->method('dispatch');

        $userManagement = $this->createStub(UserManagement::class);
        $userManagement->method('authenticateWithRefreshToken')
            ->willReturn($this->createResponse('org_other'));

        $driver = $this->createDriver(self::ORGANISATION_ID, $userManagement, $dispatcher);

        $user = $this->createUser();
        $user->setOAuthParams([
            OAuthDriverInterface::PARAM_ACCESS_TOKEN => 'expired',
            OAuthDriverInterface::PARAM_REFRESH_TOKEN => 'refresh',
        ]);

        try {
            $driver->refreshUser($user);
            self::fail('Expected an AuthenticationException');
        } catch (AuthenticationException $exception) {
            self::assertInstanceOf(InvalidOrganisationException::class, $exception->getPrevious());
        }
    }

    private function createCallbackRequest(): Request
    {
        $state = StringHelper::urlSafeBase64Encode(\json_encode([
            OAuthDriverInterface::PARAM_LAST_URL => 'https://tenancy.example.com/',
            'token' => 'csrf',
        ], \JSON_THROW_ON_ERROR));

        return Request::create('/oauth/callback', Request::METHOD_GET, [
            'code' => 'code',
            'state' => $state,
        ]);
    }

    private function createDriver(
        ?string $organisationId,
        UserManagement $userManagement,
        EventDispatcherInterface $dispatcher,
    ): WorkOsOAuthDriver {
        // An empty JWK set makes the access token undecodable, the path the driver already tolerates
        $cache = $this->createStub(CacheInterface::class);
        $cache->method('get')
            ->willReturn([]);

        $csrfTokenManager = $this->createStub(CsrfTokenManagerInterface::class);
        $csrfTokenManager->method('isTokenValid')
            ->willReturn(true);

        $workOs = $this->createStub(WorkOS::class);
        $workOs->method('userManagement')
            ->willReturn($userManagement);

        return new WorkOsOAuthDriver(
            cache: $cache,
            csrfTokenManager: $csrfTokenManager,
            eventDispatcher: $dispatcher,
            logger: new NullLogger(),
            workOs: $workOs,
            firewallName: 'ui',
            clientId: 'client_test',
            logoutRedirectRouteName: 'logout',
            callbackRouteName: 'callback',
            urlGenerator: $this->createStub(UrlGeneratorInterface::class),
            security: $this->createStub(Security::class),
            organisationId: $organisationId,
        );
    }

    private function createResponse(?string $organisationId): AuthenticateResponse
    {
        $now = new DateTimeImmutable();

        return new AuthenticateResponse(
            user: new User(
                object: 'user',
                id: 'user_123',
                firstName: null,
                lastName: null,
                profilePictureUrl: null,
                email: 'user@example.com',
                emailVerified: true,
                externalId: null,
                lastSignInAt: null,
                createdAt: $now,
                updatedAt: $now,
            ),
            accessToken: 'access',
            refreshToken: 'refresh',
            organizationId: $organisationId,
        );
    }

    private function createUser(): OAuthUserInterface
    {
        return new class() implements OAuthUserInterface {
            use OAuthUserTrait;

            public function getRoles(): array
            {
                return [];
            }

            public function getUserIdentifier(): string
            {
                return 'user_123';
            }
        };
    }
}
