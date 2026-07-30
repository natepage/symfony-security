<?php
declare(strict_types=1);

namespace NatePage\SymfonySecurity\OAuth\ValueObject;

use DateTimeInterface;

final readonly class Invitation
{
    public function __construct(
        public string $id,
        public string $status,
        public string $token,
        public DateTimeInterface $expiresAt,
        public DateTimeInterface $createdAt,
    ) {
    }
}
