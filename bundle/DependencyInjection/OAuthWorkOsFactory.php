<?php
declare(strict_types=1);

namespace NatePage\SymfonySecurity\Bundle\DependencyInjection;

use NatePage\SymfonySecurity\OAuth\Authenticator\OAuthAuthenticator;
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

    private array $callbackRoutesMapping = [];

    private array $patterns = [];

    public function addConfiguration(NodeDefinition $builder): void
    {
        $builder
            ->children()
                ->scalarNode('api_key')->isRequired()->end()
                ->scalarNode('client_id')->isRequired()->end()
                ->scalarNode('logout_redirect_route')->isRequired()->end()
                ->scalarNode('provider')->end()
                ->scalarNode('auth_provider')->defaultNull()->end()
                ->scalarNode('organisation_id')->defaultNull()->end()
                ->scalarNode('user_class')->isRequired()->end()
            ->end();
    }

    public function createAuthenticator(
        ContainerBuilder $container,
        string $firewallName,
        array $config,
        string $userProviderId
    ): string|array {
        $authenticatorId = \sprintf('natepage.security.authenticator.workos.%s', $firewallName);
        $callbackRouteName = \sprintf('natepage_security_oauth_callback_%s', $firewallName);
        $driverId = \sprintf('natepage.security.oauth.driver.%s', $firewallName);
        $logoutListenerId = \sprintf('natepage.security.logout_listener.workos.%s', $firewallName);
        $workOsId = \sprintf('natepage.security.oauth.workos.%s', $firewallName);

        // Actual WorkOS class (3rd party)
        $container->setDefinition($workOsId, (new Definition(WorkOS::class))
            ->setFactory([new Reference(WorkOsFactory::class), 'create'])
            ->setArgument('$apiKey', $config['api_key'])
            ->setArgument('$clientId', $config['client_id']));

        // OAuth driver
        $container->setDefinition($driverId, (new ChildDefinition(WorkOsOAuthDriver::class))
            ->setArgument('$workOs', new Reference($workOsId))
            ->setArgument('$firewallName', $firewallName)
            ->setArgument('$clientId', $config['client_id'])
            ->setArgument('$callbackRouteName', $callbackRouteName)
            ->setArgument('$logoutRedirectRouteName', $config['logout_redirect_route'])
            ->setArgument('$organisationId', $config['organisation_id'])
            ->setArgument('$authProvider', $config['auth_provider']));

        // Symfony Authenticator + Entrypoint using OAuth driver
        $container->setDefinition($authenticatorId, (new ChildDefinition(OAuthAuthenticator::class))
            ->setArgument('$oauthDriver', new Reference($driverId)));

        // Symfony UserProvider using OAuth driver
        $container->setDefinition($userProviderId, (new ChildDefinition(OAuthUserProvider::class))
            ->setArgument('$oauthDriver', new Reference($driverId)))
            ->setArgument('$userClass', $config['user_class']);

        // Logout Listener to redirect to right route
        $container->setDefinition($logoutListenerId, (new ChildDefinition(OAuthLogoutListener::class))
            ->setArgument('$oauthDriver', new Reference($driverId))
            ->addTag('kernel.event_listener', ['event' => LogoutEvent::class]));

        // Callback route loader
        $this->callbackRoutesMapping[$callbackRouteName] = $this->patterns[$firewallName] ?? null;
        // Fixed service id so it gets overridden with latest mapping
        $callbackRouteLoaderId = 'natepage.security.route_loader.workos';
        $container->setDefinition($callbackRouteLoaderId, (new Definition(CallbackRouteLoader::class))
            ->setArgument('$routesMapping', $this->callbackRoutesMapping)
            ->addTag('routing.loader'));

        return $authenticatorId;
    }

    public function getKey(): string
    {
        return self::KEY;
    }

    public function getPriority(): int
    {
        return self::PRIORITY;
    }

    public function prepend(ContainerBuilder $container): void
    {
        $this->patterns = [];
        $securityConfigs = $container->getExtensionConfig('security');
        $sanitizedKey = \str_replace('-', '_', self::KEY);

        foreach (\array_reverse($securityConfigs) as $config) {
            foreach ($config['firewalls'] ?? [] as $firewallName => $firewallConfig) {
                if (isset($firewallConfig[$sanitizedKey], $firewallConfig['pattern'])
                    && (isset($this->patterns[$firewallName]) === false)) {
                    $this->patterns[$firewallName] = $firewallConfig['pattern'];
                }
            }
        }
    }
}
