<?php
declare(strict_types=1);

namespace NatePage\SymfonySecurity\OAuth\Event;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

final class OAuthAuthenticationSuccessEvent
{
    private ?Response $response = null;

    public function __construct(
        private readonly Request $request,
        private readonly TokenInterface $token,
        private readonly string $firewallName,
    ) {
    }

    public function getFirewallName(): string
    {
        return $this->firewallName;
    }

    public function getRequest(): Request
    {
        return $this->request;
    }

    public function getResponse(): ?Response
    {
        return $this->response;
    }

    public function getToken(): TokenInterface
    {
        return $this->token;
    }

    public function setResponse(Response $response): void
    {
        $this->response = $response;
    }
}
