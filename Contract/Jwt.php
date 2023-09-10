<?php
declare(strict_types=1);

namespace Jwt\Contract;

use Jwt\Exception\SignerFailure;

interface Jwt
{
    /**
     * Returns a signed JWT string.
     *
     * @return string Encoded and signed JWT
     * @throws SignerFailure if signing the JWT fails
     */
    public function signedJwt(): string;
}