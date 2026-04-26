<?php
declare(strict_types=1);

namespace NatePage\SymfonySecurity\Bundle;

use NatePage\SymfonySecurity\Bundle\Enum\ConfigTag;
use NatePage\SymfonySecurity\OAuth\Driver\OAuthDriverInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;

final class SymfonySecurityBundle extends AbstractBundle
{
    public function __construct()
    {
        $this->path = \realpath(__DIR__);
    }

    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $builder
            ->registerForAutoconfiguration(OAuthDriverInterface::class)
            ->addTag(ConfigTag::OAuthDriver->value);

        $container->import('config/services.php');
    }
}
