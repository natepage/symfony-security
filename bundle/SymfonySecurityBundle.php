<?php
declare(strict_types=1);

namespace NatePage\SymfonySecurity\Bundle;

use NatePage\SymfonySecurity\Bundle\DependencyInjection\OAuthFactory;
use NatePage\SymfonySecurity\Bundle\Enum\ConfigTag;
use NatePage\SymfonySecurity\OAuth\Driver\OAuthDriverInterface;
use Symfony\Bundle\SecurityBundle\DependencyInjection\SecurityExtension;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;

final class SymfonySecurityBundle extends AbstractBundle
{
    public function __construct()
    {
        $this->path = \realpath(__DIR__);
    }

    public function build(ContainerBuilder $container): void
    {
        parent::build($container);

        /** @var SecurityExtension $extension */
        $extension = $container->getExtension('security');
        $extension->addAuthenticatorFactory(new OAuthFactory());
    }

    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $builder
            ->registerForAutoconfiguration(OAuthDriverInterface::class)
            ->addTag(ConfigTag::OAuthDriver->value);

        $container->import('config/services.php');
    }
}
