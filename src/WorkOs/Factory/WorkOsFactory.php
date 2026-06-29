<?php
declare(strict_types=1);

namespace NatePage\SymfonySecurity\WorkOs\Factory;

use Psr\Log\LoggerInterface;
use WorkOS\WorkOS;

final readonly class WorkOsFactory
{
    public function __construct(
        private LoggerInterface $logger,
    ) {
    }

    public function create(string $apiKey, string $clientId): WorkOS
    {
        $this->logger->debug('Creating WorkOS instance', [
            'apiKey' => $apiKey,
            'clientId' => $clientId,
        ]);

        return new WorkOS($apiKey, $clientId);
    }
}
