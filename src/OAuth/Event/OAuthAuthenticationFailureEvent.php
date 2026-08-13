<?php
declare(strict_types=1);

namespace NatePage\SymfonySecurity\OAuth\Event;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

final class OAuthAuthenticationFailureEvent
{
    private ?Response $response = null;

    public function __construct(
        private readonly Request $request,
        private readonly AuthenticationException $exception
    ) {
    }

    public function getAuthenticationException(): AuthenticationException
    {
        return $this->exception;
    }

    public function getRequest(): Request
    {
        return $this->request;
    }

    public function getResponse(): ?Response
    {
        return $this->response;
    }

    public function setResponse(Response $response): void
    {
        $this->response = $response;
    }
}
