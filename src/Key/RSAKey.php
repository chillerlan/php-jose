<?php
/**
 * Class RSAKey
 *
 * @created      19.08.2024
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2024 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\JOSE\Key;

use chillerlan\JOSE\Util;
use GMP;
use InvalidArgumentException;
use OpenSSLAsymmetricKey;
use RuntimeException;
use function array_map;
use function chr;
use function gmp_cmp;
use function gmp_export;
use function gmp_init;
use function gmp_invert;
use function gmp_sub;
use function ltrim;
use function openssl_pkey_export;
use function openssl_pkey_get_details;
use function openssl_pkey_new;
use function ord;
use function pack;
use function strlen;
use const OPENSSL_KEYTYPE_RSA;

/**
 * RSA Key
 *
 * @see \chillerlan\JOSE\Algorithms\Signature\RSA
 * @see \chillerlan\JOSE\Algorithms\Signature\RSAPSS
 * @see \chillerlan\JOSE\Key\RSAKey
 *
 * @link https://datatracker.ietf.org/doc/html/rfc7518#section-6.3
 *
 * RSA JWK to PEM converter, derived from phpseclib
 *
 * @link https://github.com/phpseclib/phpseclib/blob/4da3ee3867a4d7b06f60be0eb93efec9973adcfb/phpseclib/Crypt/RSA.php
 * @link https://github.com/phpseclib/phpseclib/blob/4da3ee3867a4d7b06f60be0eb93efec9973adcfb/phpseclib/Math/BigInteger/Engines/GMP.php
 * @link https://github.com/phpseclib/phpseclib/blob/4da3ee3867a4d7b06f60be0eb93efec9973adcfb/phpseclib/File/ASN1.php
 */
final class RSAKey extends OpenSSLKeyAbstract{

	public const KTY = 'RSA';

	public const PARAMS_PRIVATE      = ['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi'];
	public const PARAMS_PUBLIC       = ['n', 'e'];

	public const PARAMS_OPENSSL      = ['n', 'e', 'd', 'p', 'q', 'dmp1', 'dmq1', 'iqmp'];
	public const PARAMS_OTHER_PRIMES = ['r', 'd', 't'];

	private const ASN1_TYPE_INTEGER  = 0x02;
	private const ASN1_TYPE_SEQUENCE = 0x10;

	private const RSAPublicKey = [
		'type'     => self::ASN1_TYPE_SEQUENCE,
		'children' => [
			'n' => ['type' => self::ASN1_TYPE_INTEGER],
			'e' => ['type' => self::ASN1_TYPE_INTEGER],
		],
	];

	private const RSAPrivateKey = [
		'type'     => self::ASN1_TYPE_SEQUENCE,
		'children' => [
			'version' => ['type' => self::ASN1_TYPE_INTEGER], // always 0, "two-prime"
			'n'       => ['type' => self::ASN1_TYPE_INTEGER], // modulus
			'e'       => ['type' => self::ASN1_TYPE_INTEGER], // publicExponent
			'd'       => ['type' => self::ASN1_TYPE_INTEGER], // privateExponent
			'p'       => ['type' => self::ASN1_TYPE_INTEGER], // prime1
			'q'       => ['type' => self::ASN1_TYPE_INTEGER], // prime2
			'dp'      => ['type' => self::ASN1_TYPE_INTEGER, 'optional' => true], // exponent1, d mod (p-1)
			'dq'      => ['type' => self::ASN1_TYPE_INTEGER, 'optional' => true], // exponent2, d mod (q-1)
			'qi'      => ['type' => self::ASN1_TYPE_INTEGER, 'optional' => true], // coefficient, (inverse of q) mod p
			// other prime info https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.7
			'oth'     => [
				'type'     => self::ASN1_TYPE_SEQUENCE,
				'optional' => true,
				'children' => [
					'type'     => self::ASN1_TYPE_SEQUENCE,
					'children' => [
						'r' => ['type' => self::ASN1_TYPE_INTEGER], // prime factor
						'd' => ['type' => self::ASN1_TYPE_INTEGER], // factor CRT exponent
						't' => ['type' => self::ASN1_TYPE_INTEGER], // factor CRT coefficient
					],
				],
			],
		],
	];

	public function create(string|null $kid = null, string|null $use = null, int $size = 4096):array{
		return $this->toArray($this->createKey($size), true, $kid, $use);
	}

	public function createPEM(int $size = 4096):string{

		if(openssl_pkey_export($this->createKey($size), $pem) === false){
			throw new RuntimeException('unable to export the key');
		}

		return $pem;
	}

	public function privateKeyToPEM(array $jwk):string{
		$jwk = $this->parseKey($jwk, self::PARAMS_PRIVATE);

		if(!$jwk['p'] instanceof GMP){
			throw new RuntimeException('no primes given');
		}

		$der = $this->encodeDER($jwk, self::RSAPrivateKey);

		return Util::formatPEM($der, 'RSA PRIVATE');
	}

	public function publicKeyToPEM(array $jwk):string{
		$jwk = $this->parseKey($jwk, self::PARAMS_PUBLIC);
		$der = $this->encodeDER($jwk, self::RSAPublicKey);

		return Util::formatPEM($der, 'RSA PUBLIC');
	}

	/**
	 * @see \openssl_pkey_get_private()
	 * @see \openssl_pkey_get_public()
	 */
	protected static function parseJWK(array $jsonKeyData):array{
		$rsaKey  = new self;
		$public  = $rsaKey->publicKeyToPEM($jsonKeyData);
		$private = null;

		if(isset($jsonKeyData['d'])){
			$private = $rsaKey->privateKeyToPEM($jsonKeyData);
		}

		return [$private, $public];
	}

	protected function toArray(OpenSSLAsymmetricKey $key, bool $private, string|null $kid = null, string|null $use = null):array{
		$details = openssl_pkey_get_details($key);

		if($details === false){
			throw new RuntimeException('could not get key details');
		}

		if($details['type'] !== OPENSSL_KEYTYPE_RSA  || !isset($details['rsa'])){
			throw new InvalidArgumentException('the given key is not a valid RSA key');
		}

		$jwk = $this->addInformationalValues(['kty' => 'RSA'], $kid, $use);

		$params = self::PARAMS_PUBLIC;

		if($private === true){
			$params = self::PARAMS_OPENSSL;
		}

		foreach($params as $i => $param){
			if(isset($details['rsa'][$param])){
				$jwk[self::PARAMS_PRIVATE[$i]] = Util::base64encode($details['rsa'][$param]);
			}
		}

		return $jwk;
	}

	private function createKey(int $size):OpenSSLAsymmetricKey{

		if($size < 2048){
			throw new InvalidArgumentException('key size too small (min 2048)');
		}

		if(($size % 8) !== 0){
			throw new InvalidArgumentException('key size must be divisible by 8');
		}

		$key = openssl_pkey_new([
			'private_key_bits' => $size,
			'private_key_type' => OPENSSL_KEYTYPE_RSA,
		]);

		if($key === false){
			throw new RuntimeException('unable to create the key');
		}

		return $key;
	}

	private function parseKey(array $keyData, array $keyParams):array{
		$key = Util::filterKeyParams($keyData, $keyParams);

		if(!isset($key['n'], $key['e'])){
			throw new InvalidArgumentException('RSA keys must contain values for both "n" and "e"');
		}

		$key = array_map(gmp_import(...), $key);

		if(!isset($key['d'], $key['p'], $key['q'])){
			return $key;
		}

		$version = 0; // two-prime

		if(isset($keyData['oth'])){
			throw new InvalidArgumentException('RSA key param "oth" (other primes info) not supported');
/*
			if(is_array($keyData['oth'])){
				$oth = [];

				foreach($keyData['oth'] as $prime){
					$otherPrimes = Util::parseKeyParams($prime, self::PARAMS_OTHER_PRIMES);

					if(!isset($otherPrimes['r'], $otherPrimes['d'], $otherPrimes['t'])){
						continue;
					}

					$oth[] = array_map(gmp_import(...), $otherPrimes);
				}

				if(!empty($oth)){
					$key['oth'] = $oth;
					$version = 1; // multi
				}
			}
*/
		}

		$key['version']   = gmp_init($version, 10);
		$key['dp']      ??= gmp_invert($key['e'], gmp_sub($key['p'], 1));
		$key['dq']      ??= gmp_invert($key['e'], gmp_sub($key['q'], 1));
		$key['qi']      ??= gmp_invert($key['q'], $key['p']);

		return $key;
	}

	private function encodeDER(GMP|array|string $source, array $mapping):string{
		$tag   = $mapping['type'];
		$value = '';

		if($tag === self::ASN1_TYPE_SEQUENCE){
			$tag |= 0x20; // set the constructed bit

			foreach($mapping['children'] as $key => $child){

				if(!isset($source[$key]) && isset($child['optional'])){
					continue;
				}

				// recursion
				$value .= $this->encodeDER($source[$key], $child);
			}
		}
		elseif($tag === self::ASN1_TYPE_INTEGER){
			$value = $this->toBytes($source);

			if($value === ''){
				$value = "\x00";
			}
		}

		return chr($tag).$this->encodeLength(strlen($value)).$value;
	}

	private function encodeLength(int $length):string{

		if($length <= 0x7f){
			return chr($length);
		}

		$temp = ltrim(pack('N', $length), chr(0));

		return pack('Ca*', (0x80 | strlen($temp)), $temp);
	}

	private function toBytes(GMP $gmp):string{

		if(gmp_cmp($gmp, 0) === 0){
			return '';
		}

		$bytes = gmp_export($gmp);

		if((ord($bytes[0]) & 0x80) > 0){
			return "\x00".$bytes;
		}

		return ltrim($bytes, "\x00");
	}

}
