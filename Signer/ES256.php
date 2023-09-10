<?php
declare(strict_types=1);

namespace Jwt\Signer;

use ErrorException;
use Jwt\Contract\Signer as SignerInterface;
use Jwt\Exception\KeyFileOpenFailure;
use Jwt\Exception\SignerFailure;
use Jwt\SignatureConverter;

use function base64_decode;
use function chunk_split;
use function fgets;
use function fopen;
use function mb_strlen;
use function openssl_sign;
use function restore_error_handler;
use function set_error_handler;
use function str_contains;
use function str_starts_with;
use function trim;

use const OPENSSL_ALGO_SHA256;

final class ES256 implements SignerInterface
{
    /**
     * ES256 constructor.
     *
     * @param string $privateKey Server private key in PEM format or a path to a file
     * @throws KeyFileOpenFailure if the key file is in invalid format
     */
    public function __construct(private string $privateKey)
    {
        if (!str_contains($privateKey, "\n")) {
            // Assume file
            $this->setPrivateKeyFromFile($privateKey);
        }

        throw new KeyFileOpenFailure('Invalid key file format');
    }

    public function algorithmName(): string
    {
        return 'ES256';
    }

    public function signature(string $jwtHeader, string $jwtPayload): string
    {
        $unsignedToken = $jwtHeader . '.' . $jwtPayload;

        try {
            set_error_handler(static function (int $severity, string $message, string $file, int $line): bool {
                throw new ErrorException($message, $severity, $severity, $file, $line);
            });

            openssl_sign($unsignedToken, $signature, $this->privateKey, OPENSSL_ALGO_SHA256);
        }
        catch (ErrorException $e) {
            throw new SignerFailure(
                'OpenSSL failed (' . $e->getCode() . '): ' . $e->getMessage(), $e->getCode(), $e
            );
        } finally {
            restore_error_handler();
        }

        if (empty($signature)) {
            throw new SignerFailure('OpenSSL failed: Empty signature');
        }

        // SHA256 DER signature is always 6-72 bytes:
        // 2 byte DER header + 2 byte R header (+ 1 byte R padding if first R byte is >0x7F) + 0-32 byte R data (left trimmed 0x00)
        // + 2 byte S header (+ 1 byte S padding if first S byte is >0x7F) + 0-32 byte S data (left trimmed 0x00)
        $signatureLength = mb_strlen($signature, '8bit');
        if ($signatureLength < 6 || $signatureLength > 72) {
            throw new SignerFailure(
                'Invalid response from OpenSSL: Signature length (' . $signatureLength . ') is not 6-72 bytes'
            );
        }

        $signature = SignatureConverter::derP256SignatureToRaw($signature);

        if (empty($signature)) {
            throw new SignerFailure('Signing the JWT failed: Empty signature');
        }

        if (mb_strlen($signature, '8bit') !== 64) {
            throw new SignerFailure('Signing the JWT failed: Signature length not 64 bytes');
        }

        return $signature;
    }

    /**
     * Sets the private key to be used when signing the JWT from $keyFile
     * or throws a FileNotFoundException if the file does not exist.
     *
     * @param string $keyFile The file to read, an EC private key in PEM format
     * @throws KeyFileOpenFailure if the requested key file does not exist or is in invalid format
     */
    private function setPrivateKeyFromFile(string $keyFile): void
    {
        $f = fopen($keyFile, 'rb');
        if (!$f) {
            throw new KeyFileOpenFailure('Could not open key file "' . $keyFile . '".');
        }

        // Get the first key from the file
        $key = '';
        $lineNum = 0;
        while (($line = fgets($f)) !== false) {
            ++$lineNum;
            $line = trim($line);

            if ($lineNum === 1) {
                if ($line !== '-----BEGIN EC PRIVATE KEY-----') {
                    throw new KeyFileOpenFailure(
                        'Invalid key file "' . $keyFile . '", expecting a singular Base64 encoded PEM EC private key file.'
                    );
                }
                continue;
            }

            if (str_starts_with($line, '-----')) {
                break;
            }

            $key .= $line;
        }

        // Test for validity
        if (base64_decode($key) === false) {
            throw new KeyFileOpenFailure(
                'Invalid key file "' . $keyFile . '", probably not a Base64 encoded PEM file.'
            );
        }

        $key = "-----BEGIN EC PRIVATE KEY-----\n"
            . chunk_split($key, 64, "\n")
            . '-----END EC PRIVATE KEY-----';

        $this->privateKey = $key;
    }
}