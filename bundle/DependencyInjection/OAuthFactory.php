<?php
declare(strict_types=1);

namespace NatePage\SymfonySecurity\Bundle\DependencyInjection;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AuthenticatorFactoryInterface;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;

final readonly class OAuthFactory implements AuthenticatorFactoryInterface
{
    public function getPriority(): int
    {
        return -50;
    }

    public function getKey(): string
    {
        return 'natepage-oauth';
    }

    public function addConfiguration(NodeDefinition $builder): void
    {
        $builder
            ->children()
                ->arrayNode('workos')
                    ->children()
                        ->scalarNode('api_key')->end()
                        ->scalarNode('client_id')->end()
                    ->end()
                ->end()
            ->end();
    }

    public function createAuthenticator(
        ContainerBuilder $container,
        string $firewallName,
        array $config,
        string $userProviderId
    ): string|array {
        return 'whatever-for-now';
    }
}
