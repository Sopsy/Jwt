<?php
declare(strict_types=1);

namespace Jwt;

use JsonException;
use BaseNEncoder\Encoder;
use BaseNEncoder\Scheme\Base64Url;
use Jwt\Contract\Jwt as JwtInterface;
use Jwt\Contract\Signer;
use Jwt\Exception\InvalidJwtArgument;
use Jwt\Exception\SignerFailure;

use function filter_var;
use function json_encode;
use function time;

use const FILTER_VALIDATE_URL;
use const JSON_THROW_ON_ERROR;

final class Jwt implements JwtInterface
{
    private readonly array $header;
    private readonly array $payload;

    /**
     * @param string $audience Audience for the JWT. Usually the push service origin
     * @param int $ttl TTL for the JWT in seconds, max is a day
     * @param string $subject Sender contact info for the push message, our "mailto:email" or a full URL
     * @param Signer $signer Signer used to sign the signature
     * @throws InvalidJwtArgument if invalid parameters are supplied
     */
    public function __construct(
        private readonly Signer $signer,
        string $audience,
        int $ttl,
        string $subject
    ) {
        /** @noinspection BypassedUrlValidationInspection
         *  Not going to create any security issues.
         */
        if (!filter_var($audience, FILTER_VALIDATE_URL)) {
            throw new InvalidJwtArgument('Invalid audience "' . $audience . '": Not a valid URL');
        }

        if ($ttl < 0 || $ttl > 86400) {
            throw new InvalidJwtArgument('Invalid TTL "' . $ttl . '": value should be between 0 and 86400');
        }

        /** @noinspection BypassedUrlValidationInspection
         *  Not going to create any security issues.
         */
        if (!filter_var($subject, FILTER_VALIDATE_URL)) {
            throw new InvalidJwtArgument('Invalid subject "' . $subject . '": Not a valid http- or mailto-link');
        }

        $this->payload = [
            'aud' => $audience,
            'exp' => time() + $ttl,
            'sub' => $subject,
        ];

        $this->header = [
            'typ' => 'JWT',
            'alg' => $signer->algorithmName(),
        ];
    }

    public function signedJwt(): string
    {
        $encoder = new Encoder(new Base64Url());

        try {
            $header = $encoder->encode(json_encode($this->header, JSON_THROW_ON_ERROR), false);
            $payload = $encoder->encode(json_encode($this->payload, JSON_THROW_ON_ERROR), false);
        } catch (JsonException $e) {
            throw new SignerFailure('Failed to JSON encode header or payload', 1, $e);
        }

        $signature = $this->signer->signature($header, $payload);
        $signature = $encoder->encode($signature, false);

        return $header . '.' . $payload . '.' . $signature;
    }
}