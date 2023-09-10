<?php
declare(strict_types=1);

namespace Jwt;

use InvalidArgumentException;

use function ltrim;
use function mb_substr;
use function ord;
use function str_pad;

use const STR_PAD_LEFT;

final class SignatureConverter
{

    /**
     * A stupid function which handles only P256 DER signature file conversion to a raw 64 byte signature
     * to be used when signing a JWT.
     *
     * @param string $signature DER encoded P256 signature
     * @return string signature in binary format
     */
    public static function derP256SignatureToRaw(string $signature): string
    {
        // Needs to be a DER with compound structure (first byte needs to be 0x30)
        if ($signature[0] !== "\x30") {
            throw new InvalidArgumentException('Invalid DER signature, not a compound structure (0x30).');
        }

        // Sequence for P256 signature should be between 4 and 70 bytes
        $sequenceLength = ord($signature[1]);
        if ($sequenceLength < 4 || $sequenceLength > 70) {
            throw new InvalidArgumentException('Invalid DER signature, sequence length is not 4-70 bytes.');
        }

        // ---- Get R ----
        // R needs to be integer (third byte needs to be 0x02)
        if ($signature[2] !== "\x02") {
            throw new InvalidArgumentException('Invalid DER signature, R is not an integer (0x02).');
        }

        // Get R length from its header (fourth byte)
        $rLen = ord($signature[3]);

        // If length is 33, the first data byte should be 0x00 to indicate an unsigned int
        if ($rLen === 33 && $signature[4] !== "\x00") {
            throw new InvalidArgumentException('Invalid DER signature, R length is 33 bytes and its first byte is not 0x00.');
        }

        // Get R from the signature
        $r = self::getSignaturePart($signature, 4, $rLen);

        // ---- Get S ----
        // S needs to be integer
        if ($signature[4 + $rLen] !== "\x02") {
            throw new InvalidArgumentException('Invalid DER signature, S is not an integer (0x02).');
        }

        // Get S length from its header (skip DER and R header + R + S header first byte)
        $sLen = ord(mb_substr($signature, 4 + $rLen + 1, 1, '8bit'));

        // Get S from the signature (skip R header + R + S header)
        $sFirstByte = 4 + $rLen + 2;
        if ($sLen === 33 && $signature[$sFirstByte] !== "\x00") {
            throw new InvalidArgumentException('Invalid DER signature, S length is 33 bytes and its first byte is not 0x00.');
        }

        // Get S from the signature
        $s = self::getSignaturePart($signature, $sFirstByte, $sLen);

        return $r . $s;
    }

    /**
     * Returns a signature part (R or S) from a full DER encoded P256 signature
     *
     * @param string $signature Full DER encoded P256 signature
     * @param int $firstByte First byte of the signature part to get
     * @param int $partLength Length of the signature part to get in bytes
     * @return string Signature part (R or S)
     */
    private static function getSignaturePart(string $signature, int $firstByte, int $partLength): string
    {
        // Get part from the signature
        $part = mb_substr($signature, $firstByte, $partLength, '8bit');

        // Remove possible unsigned int indicator
        $part = ltrim($part, "\x00");

        // DER left trims 0x00 from signature values, restore it
        return str_pad($part, 32, "\x00", STR_PAD_LEFT);
    }
}