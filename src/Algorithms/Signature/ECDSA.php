<?php
/**
 * Class ECDSA
 *
 * @created      09.08.2024
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2024 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\JOSE\Algorithms\Signature;

use chillerlan\JOSE\Algorithms\OpenSSLAbstract;
use chillerlan\JOSE\Key\JWK;
use InvalidArgumentException;
use function dechex;
use function hexdec;
use function intdiv;
use function sodium_bin2hex;
use function sodium_hex2bin;
use function str_pad;
use function strlen;
use function substr;
use const OPENSSL_ALGO_SHA256;
use const OPENSSL_ALGO_SHA384;
use const OPENSSL_ALGO_SHA512;
use const OPENSSL_KEYTYPE_EC;
use const STR_PAD_LEFT;

/**
 * ECDSA Signature Algorithm
 *
 * @link https://datatracker.ietf.org/doc/html/rfc7518#section-3.4
 * @link https://github.com/web-token/jwt-framework/blob/4af252f28996bfb8ce5eac78037a555dce222829/src/Library/Core/Util/ECSignature.php
 */
final class ECDSA extends OpenSSLAbstract implements SignatureAlgorithm{

	public const SUPPORTED_ALGOS = [
		'ES256'  => OPENSSL_ALGO_SHA256,
		'ES256K' => OPENSSL_ALGO_SHA256,
		'ES384'  => OPENSSL_ALGO_SHA384,
		'ES512'  => OPENSSL_ALGO_SHA512,
	];

	private const META = [
		'ES256'  => [256, 64, 'P-256'],
		'ES256K' => [256, 64, 'P-256K'],
		'ES384'  => [384, 96, 'P-384'],
		'ES512'  => [521, 132, 'P-521'],
	];

	protected const KEYTYPE = OPENSSL_KEYTYPE_EC;

	private const BYTE_SIZE = 2;

	private const ASN1_SEQUENCE          = '30';
	private const ASN1_INTEGER           = '02';
	private const ASN1_LENGTH_2BYTES     = '81';
	private const ASN1_BIG_INTEGER_LIMIT = '7f';
	private const ASN1_NEGATIVE_INTEGER  = '00';

	private int $keyLength;
	private int $signaturePartLength;
#	private string $crv;

	public function __construct(JWK $jwk, string $algo, string|null $passphrase = null){
		parent::__construct($jwk, $algo, $passphrase);

		[$this->keyLength, $this->signaturePartLength, /* $this->crv */] = self::META[$this->algo];
	}

	public function sign(string $message):string{
		return $this->fromAsn1($this->signMessage($message));
	}

	public function verify(string $message, string $signature):bool{
		return $this->verifySignature($message, $this->toAsn1($signature));
	}

	protected function checkKeyLength(int $bits):bool{
		return $bits === $this->keyLength;
	}

	private function toAsn1(string $signature):string{
		$signature = sodium_bin2hex($signature);

		if($this->octetLength($signature) !== $this->signaturePartLength){
			throw new InvalidArgumentException('Invalid signature length.');
		}

		$pointR  = $this->preparePositiveInteger(substr($signature, 0, $this->signaturePartLength));
		$pointS  = $this->preparePositiveInteger(substr($signature, $this->signaturePartLength));
		$lengthR = $this->octetLength($pointR);
		$lengthS = $this->octetLength($pointS);

		$totalLength  = ($lengthR + $lengthS + 2 * self::BYTE_SIZE);
		$lengthPrefix = '';

		if($totalLength > 128){ // ASN1_MAX_SINGLE_BYTE
			$lengthPrefix = self::ASN1_LENGTH_2BYTES;
		}

		return sodium_hex2bin(
			self::ASN1_SEQUENCE.
			$lengthPrefix.
			dechex($totalLength).
			self::ASN1_INTEGER.
			dechex($lengthR).
			$pointR.
			self::ASN1_INTEGER.
			dechex($lengthS).
			$pointS,
		);
	}

	private function octetLength(string $data):int{
		return intdiv(strlen($data), self::BYTE_SIZE);
	}

	private function preparePositiveInteger(string $data):string{

		if(substr($data, 0, self::BYTE_SIZE) > self::ASN1_BIG_INTEGER_LIMIT){
			return self::ASN1_NEGATIVE_INTEGER.$data;
		}

		while(
			str_starts_with($data, self::ASN1_NEGATIVE_INTEGER)
			&& substr($data, 2, self::BYTE_SIZE) <= self::ASN1_BIG_INTEGER_LIMIT
		){
			$data = substr($data, 2);
		}

		return $data;
	}

	private function fromAsn1(string $signature):string{
		$message  = sodium_bin2hex($signature);
		$position = 0;

		if($this->readAsn1Content($message, $position, self::BYTE_SIZE) !== self::ASN1_SEQUENCE){
			throw new InvalidArgumentException('Invalid data. Should start with a sequence.'); // @codeCoverageIgnore
		}

		if($this->readAsn1Content($message, $position, self::BYTE_SIZE) === self::ASN1_LENGTH_2BYTES){
			$position += self::BYTE_SIZE;
		}

		$pointR = $this->retrievePositiveInteger($message, $position);
		$pointS = $this->retrievePositiveInteger($message, $position);

		return sodium_hex2bin(
			str_pad($pointR, $this->signaturePartLength, '0', STR_PAD_LEFT).
			str_pad($pointS, $this->signaturePartLength, '0', STR_PAD_LEFT),
		);
	}

	private function readAsn1Content(string $message, int &$position, int $length):string{
		$content   = substr($message, $position, $length);
		$position += $length;

		return $content;
	}

	private function retrievePositiveInteger(string $message, int &$position):string{

		if($this->readAsn1Content($message, $position, self::BYTE_SIZE) !== self::ASN1_INTEGER){
			throw new InvalidArgumentException('Invalid data. Should contain an integer.'); // @codeCoverageIgnore
		}

		$length = (int)hexdec($this->readAsn1Content($message, $position, self::BYTE_SIZE));
		$data   = $this->readAsn1Content($message, $position, ($length * self::BYTE_SIZE));

		while(
			str_starts_with($data, self::ASN1_NEGATIVE_INTEGER)
			&& substr($data, 2, self::BYTE_SIZE) > self::ASN1_BIG_INTEGER_LIMIT
		){
			$data = substr($data, 2);
		}

		return $data;
	}

}
