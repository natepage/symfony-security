<?php
declare(strict_types=1);

namespace Symfony\Component\DependencyInjection\Loader\Configurator;

use NatePage\SymfonySecurity\OAuth\Authenticator\OAuthAuthenticator;
use NatePage\SymfonySecurity\OAuth\Entrypoint\OAuthEntrypoint;
use NatePage\SymfonySecurity\OAuth\Listener\OAuthLogoutListener;
use NatePage\SymfonySecurity\OAuth\Provider\OAuthUserProvider;
use NatePage\SymfonySecurity\WorkOs\Driver\WorkOsOAuthDriver;
use NatePage\SymfonySecurity\WorkOs\Factory\WorkOsFactory;

return static function (ContainerConfigurator $containerConfigurator): void {
    $services = $containerConfigurator->services();

    $services->defaults()
        ->autowire()
        ->autoconfigure();

    // Security
    $abstractServices = [
        OAuthAuthenticator::class,
        OAuthEntrypoint::class,
        OAuthLogoutListener::class,
        OAuthUserProvider::class,
    ];

    foreach ($abstractServices as $class) {
        $services
            ->set($class)
            ->abstract();
    }

    // WorkOS
    $services->set(WorkOsFactory::class);

    $services
        ->set(WorkOsOAuthDriver::class)
        ->abstract();
};
