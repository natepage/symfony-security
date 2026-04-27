<?php
declare(strict_types=1);

namespace NatePage\SymfonySecurity\Bundle\DependencyInjection;

use NatePage\SymfonySecurity\OAuth\Authenticator\OAuthAuthenticator;
use NatePage\SymfonySecurity\OAuth\Entrypoint\OAuthEntrypoint;
use NatePage\SymfonySecurity\OAuth\Listener\OAuthLogoutListener;
use NatePage\SymfonySecurity\OAuth\Provider\OAuthUserProvider;
use NatePage\SymfonySecurity\OAuth\Routing\CallbackRouteLoader;
use NatePage\SymfonySecurity\WorkOs\Driver\WorkOsOAuthDriver;
use NatePage\SymfonySecurity\WorkOs\Factory\WorkOsFactory;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AuthenticatorFactoryInterface;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\Security\Http\Event\LogoutEvent;
use WorkOS\WorkOS;

final class OAuthWorkOsFactory implements AuthenticatorFactoryInterface, PrependExtensionInterface
{
    private const string KEY = 'oauth-workos';
    private const int PRIORITY = -50;

    public function addConfiguration(NodeDefinition $builder): void
    {
        $builder
            ->children()
                ->scalarNode('pattern')->isRequired()->end()
                ->scalarNode('api_key')->isRequired()->end()
                ->scalarNode('client_id')->isRequired()->end()
                ->scalarNode('logout_redirect_route')->isRequired()->end()
                ->scalarNode('provider')->end()
            ->end();
    }

    public function createAuthenticator(
        ContainerBuilder $container,
        string $firewallName,
        array $config,
        string $userProviderId
    ): string|array {
        $authenticatorId = \sprintf('natepage.security.authenticator.workos.%s', $firewallName);
        $callbackRouteLoaderId = \sprintf('natepage.security.route_loader.workos.%s', $firewallName);
        $callbackRouteName = \sprintf('natepage_security_oauth_callback_%s', $firewallName);
        $driverId = \sprintf('natepage.security.oauth.driver.%s', $firewallName);
        $entrypointId = \sprintf('natepage.security.entrypoint.workos.%s', $firewallName);
        $logoutListenerId = \sprintf('natepage.security.entrypoint.workos.%s', $firewallName);
        $workOsId = \sprintf('natepage.security.oauth.workos.%s', $firewallName);

        // Actual WorkOS class (3rd party)
        $container->set($workOsId, (new Definition(WorkOS::class))
            ->setFactory([new Reference(WorkOsFactory::class), 'create'])
            ->setArgument('$apiKey', $config['api_key'])
            ->setArgument('$clientId', $config['client_id']));

        // OAuth driver
        $container->set($driverId, (new ChildDefinition(WorkOsOAuthDriver::class))
            ->setArgument('$workOs', new Reference($workOsId))
            ->setArgument('$clientId', $config['client_id'])
            ->setArgument('$callbackRouteName', $callbackRouteName)
            ->setArgument('$logoutRedirectRouteName', $config['logout_redirect_route']));

        // Symfony Authenticator using OAuth driver
        $container->set($authenticatorId, (new ChildDefinition(OAuthAuthenticator::class))
            ->setArgument('$oauthDriver', new Reference($driverId)));

        // Symfony Entrypoint using OAuth driver
        $container->set($entrypointId, (new ChildDefinition(OAuthEntrypoint::class))
            ->setArgument('$oauthDriver', new Reference($driverId)));

        // Symfony UserProvider using OAuth driver
        $container->set($config['provider'], (new ChildDefinition(OAuthUserProvider::class))
            ->setArgument('$oauthDriver', new Reference($driverId)));

        // Logout Listener to redirect to right route
        $container->set($logoutListenerId, (new ChildDefinition(OAuthLogoutListener::class))
            ->setArgument('$oauthDriver', new Reference($driverId))
            ->addTag('kernel.event_listener', ['event' => LogoutEvent::class]));

        // Callback route loader
        $container->set($callbackRouteLoaderId, (new Definition(CallbackRouteLoader::class))
            ->setArgument('$callbackRouteName', $callbackRouteName)
            ->setArgument('$pattern', $config['pattern'])
            ->addTag('routing.loader'));

        return [$authenticatorId, $entrypointId];
    }

    public function getKey(): string
    {
        return self::KEY;
    }

    public function getPriority(): int
    {
        return self::PRIORITY;
    }

    /**
     * This method is used to dynamically register the user provider for a firewall using this authenticator.
     */
    public function prepend(ContainerBuilder $container): void
    {
        $securityConfigs = $container->getExtensionConfig('security');
        foreach (\array_reverse($securityConfigs) as $config) {
            foreach ($config['firewalls'] ?? [] as $firewallName => $firewallConfig) {
                if (isset($firewallConfig[self::KEY])) {
                    $userProviderId = $this->getUserProviderId($firewallName);

                    $container->prependExtensionConfig('security', [
                        'providers' => [
                            $userProviderId => ['id' => $userProviderId],
                        ],
                        'firewalls' => [
                            $firewallName => [
                                self::KEY => [
                                    'provider' => $userProviderId,
                                ],
                            ],
                        ],
                    ]);

                    return;
                }
            }
        }
    }

    private function getUserProviderId(string $firewallName): string
    {
        return \sprintf('natepage.security.user_provider.workos.%s', $firewallName);
    }
}
