<?php
declare(strict_types=1);

namespace NatePage\SymfonySecurity\OAuth\Event;

use Symfony\Component\HttpFoundation\Response;

final class OAuthEntrypointStartForTurboFrameEvent
{
    private ?Response $response = null;

    public function __construct(
        private readonly string $authorizationUrl,
        private readonly string $frameId,
    ) {
    }

    public function getAuthorizationUrl(): string
    {
        return $this->authorizationUrl;
    }

    public function getFrameId(): string
    {
        return $this->frameId;
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
