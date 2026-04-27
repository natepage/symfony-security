<?php
declare(strict_types=1);

namespace NatePage\SymfonySecurity\WorkOs\Factory;

use WorkOS\WorkOS;

final readonly class WorkOsFactory
{
    public function create(string $apiKey, string $clientId): WorkOS
    {
        return new WorkOS($apiKey, $clientId);
    }
}
