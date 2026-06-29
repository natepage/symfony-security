<?php
declare(strict_types=1);

namespace NatePage\SymfonySecurity\OAuth\Routing;

use NatePage\SymfonySecurity\Bundle\Enum\BundleParam;
use NatePage\SymfonySecurity\OAuth\Controller\OAuthCallbackController;
use Symfony\Component\Config\Loader\Loader;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;
use function Symfony\Component\String\u;

final class CallbackRouteLoader extends Loader
{
    private bool $loaded = false;

    public function __construct(
        private readonly array $routesMapping,
        ?string $env = null
    ) {
        parent::__construct($env);
    }

    public function load(mixed $resource, ?string $type = null): RouteCollection
    {
        if ($this->loaded) {
            throw new \RuntimeException('Do not add the "oauth_callback" route loader twice.');
        }

        $routes = new RouteCollection();

        foreach ($this->routesMapping as $routeName => $pattern) {
            $path = u($pattern)
                ->trimPrefix('^')
                ->ensureStart('/')
                ->ensureEnd('/oauth/callback')
                ->toString();

            $routes->add($routeName, new Route(
                path: $path,
                defaults: [
                    '_controller' => OAuthCallbackController::class,
                ],
                methods: ['GET'],
            ));
        }

        $this->loaded = true;

        return $routes;
    }

    public function supports(mixed $resource, ?string $type = null): bool
    {
        return $type === BundleParam::RouteType->value;
    }
}
