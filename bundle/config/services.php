<?php
declare(strict_types=1);

namespace Symfony\Component\DependencyInjection\Loader\Configurator;

use NatePage\SymfonySecurity\Bundle\Enum\ConfigTag;
use NatePage\SymfonySecurity\OAuth\Authenticator\OAuthAuthenticator;
use NatePage\SymfonySecurity\OAuth\Driver\FromRequestOAuthDriverProvider;
use NatePage\SymfonySecurity\OAuth\Driver\OAuthDriverProviderInterface;
use NatePage\SymfonySecurity\OAuth\Entrypoint\OAuthEntrypoint;
use NatePage\SymfonySecurity\OAuth\Listener\OAuthLogoutListener;
use NatePage\SymfonySecurity\OAuth\Provider\OAuthUserProvider;

return static function (ContainerConfigurator $containerConfigurator): void {
    $services = $containerConfigurator->services();

    $services->defaults()
        ->autowire()
        ->autoconfigure();

    // TODO: change implementation into Security AuthenticatorFactoryInterface

    $services
        ->set(OAuthAuthenticator::class)
        ->set(OAuthEntrypoint::class)
        ->set(OAuthLogoutListener::class)
        ->set(OAuthUserProvider::class);

    $services
        ->set(OAuthDriverProviderInterface::class, FromRequestOAuthDriverProvider::class)
        ->arg('$oauthDrivers', tagged_locator(tag: ConfigTag::OAuthDriver->value, indexAttribute: 'driver'));
};
