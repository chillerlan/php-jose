<?php
/**
 * Class ECKey
 *
 * @created      19.08.2024
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2024 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\JOSE\Key;

use chillerlan\JOSE\Util;
use InvalidArgumentException;
use OpenSSLAsymmetricKey;
use RuntimeException;
use function ceil;
use function ltrim;
use function openssl_pkey_export;
use function openssl_pkey_get_details;
use function openssl_pkey_new;
use function sodium_bin2hex;
use function sodium_hex2bin;
use function sprintf;
use function str_pad;
use const OPENSSL_KEYTYPE_EC;
use const STR_PAD_LEFT;

/**
 * Elliptic Curve Key
 *
 * @see \chillerlan\JOSE\Algorithms\Signature\ECDSA
 * @see \chillerlan\JOSE\Key\ECKey
 *
 * @link https://datatracker.ietf.org/doc/html/rfc7518#section-6.2
 *
 * derived from web-token/jwt-framework
 *
 * @link https://github.com/web-token/jwt-framework/blob/4af252f28996bfb8ce5eac78037a555dce222829/src/Library/Core/Util/ECKey.php
 */
final class ECKey extends OpenSSLKeyAbstract{

	public const KTY = 'EC';

	public const CRV_P256  = 'P-256';
	public const CRV_P256K = 'P-256K';
	public const CRV_P384  = 'P-384';
	public const CRV_P521  = 'P-521';

	public const PARAMS_PRIVATE = ['x', 'y', 'd'];
	public const PARAMS_PUBLIC  = ['x', 'y'];

	// map of valid crv values (resolver)
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.1
	private const EC_CURVES = [
		'P-256'      => self::CRV_P256,
		'prime256v1' => self::CRV_P256,
		'P-256K'     => self::CRV_P256K,
		'secp256k1'  => self::CRV_P256K,
		'P-384'      => self::CRV_P384,
		'secp384r1'  => self::CRV_P384,
		'P-521'      => self::CRV_P521,
		'secp521r1'  => self::CRV_P521,
	];

	// map of crv value -> openssl name
	private const CRV_OPENSSL = [
		'P-256'      => 'prime256v1',
		'prime256v1' => 'prime256v1',
		'P-256K'     => 'secp256k1',
		'secp256k1'  => 'secp256k1',
		'P-384'      => 'secp384r1',
		'secp384r1'  => 'secp384r1',
		'P-521'      => 'secp521r1',
		'secp521r1'  => 'secp521r1',
	];

	private const p256PublicKey =
		'3059'. // SEQUENCE, length 89
		'3013'. // SEQUENCE, length 19
		'0607'. // OID, length 7
		'2a8648ce3d0201'. // 1.2.840.10045.2.1 = EC Public Key
		'0608'. // OID, length 8
		'2a8648ce3d030107'. // 1.2.840.10045.3.1.7 = P-256 Curve
		'0342'. // BIT STRING, length 66
		'00'; // prepend with NUL - pubkey will follow

	private const p256KPublicKey =
		'3056'. // SEQUENCE, length 86
		'3010'. // SEQUENCE, length 16
		'0607'. // OID, length 7
		'2a8648ce3d0201'. // 1.2.840.10045.2.1 = EC Public Key
		'0605'. // OID, length 8
		'2B8104000A'. // 1.3.132.0.10 secp256k1
		'0342'. // BIT STRING, length 66
		'00'; // prepend with NUL - pubkey will follow

	private const p384PublicKey =
		'3076'. // SEQUENCE, length 118
		'3010'. // SEQUENCE, length 16
		'0607'. // OID, length 7
		'2a8648ce3d0201'. // 1.2.840.10045.2.1 = EC Public Key
		'0605'. // OID, length 5
		'2b81040022'. // 1.3.132.0.34 = P-384 Curve
		'0362'. // BIT STRING, length 98
		'00'; // prepend with NUL - pubkey will follow

	private const p521PublicKey =
		'30819b'. // SEQUENCE, length 154
		'3010'. // SEQUENCE, length 16
		'0607'. // OID, length 7
		'2a8648ce3d0201'. // 1.2.840.10045.2.1 = EC Public Key
		'0605'. // OID, length 5
		'2b81040023'. // 1.3.132.0.35 = P-521 Curve
		'038186'. // BIT STRING, length 134
		'00'; // prepend with NUL - pubkey will follow

	private const p256PrivateKey =
		'3077'. // SEQUENCE, length 87+length($d)=32
		'020101'. // INTEGER, 1
		'0420'. // OCTET STRING, length($d) = 32
		'%s'. // PRIVATE KEY, padsize = 32
		'a00a'. // TAGGED OBJECT #0, length 10
		'0608'. // OID, length 8
		'2a8648ce3d030107'. // 1.3.132.0.34 = P-256 Curve
		'a144'. //  TAGGED OBJECT #1, length 68
		'0342'. // BIT STRING, length 66
		'00'; // prepend with NUL - pubkey will follow;

	private const p256KPrivateKey =
		'3074'. // SEQUENCE, length 84+length($d)=32
		'020101'. // INTEGER, 1
		'0420'.   // OCTET STRING, length($d) = 32
		'%s'. // PRIVATE KEY, padsize = 32
		'a007'. // TAGGED OBJECT #0, length 7
		'0605'. // OID, length 5
		'2b8104000a'. //  1.3.132.0.10 secp256k1
		'a144'. //  TAGGED OBJECT #1, length 68
		'0342'. // BIT STRING, length 66
		'00'; // prepend with NUL - pubkey will follow;

	private const p384PrivateKey =
		'3081a4'. // SEQUENCE, length 116 + length($d)=48
		'020101'. // INTEGER, 1
		'0430'.   // OCTET STRING, length($d) = 30
		'%s'. // PRIVATE KEY, padsize = 48
		'a007'. // TAGGED OBJECT #0, length 7
		'0605'. // OID, length 5
		'2b81040022'. // 1.3.132.0.34 = P-384 Curve
		'a164'. //  TAGGED OBJECT #1, length 100
		'0362'. // BIT STRING, length 98
		'00'; // prepend with NUL - pubkey will follow

	private const p521PrivateKey =
		'3081dc'. // SEQUENCE, length 154 + length($d)=66
		'020101'. // INTEGER, 1
		'0442'.   // OCTET STRING, length(d) = 66
		'%s'. // PRIVATE KEY, padsize = 66
		'a007'. // TAGGED OBJECT #0, length 7
		'0605'. // OID, length 5
		'2b81040023'. // 1.3.132.0.35 = P-521 Curve
		'a18189'. //  TAGGED OBJECT #1, length 137
		'038186'. // BIT STRING, length 134
		'00'; // prepend with NUL - pubkey will follow

	public function create(string|null $kid = null, string|null $use = null, string $crv = self::CRV_P521):array{
		return $this->toArray($this->createKey($crv), true, $kid, $use);
	}

	public function createPEM(string $crv = self::CRV_P521):string{

		if(openssl_pkey_export($this->createKey($crv), $pem) === false){
			throw new RuntimeException('unable to export the key');
		}

		return $pem;
	}

	public function privateKeyToPEM(array $jwk):string{

		if(!isset($jwk['crv'])){
			throw new InvalidArgumentException('"crv" not set');
		}

		$key = Util::filterKeyParams($jwk, self::PARAMS_PRIVATE);

		if(!isset($key['x'], $key['y'], $key['d'])){
			throw new RuntimeException('"x", "y" and/or "d" not set');
		}

		[$der, $padSize] = match($jwk['crv']){
			self::CRV_P256  => [self::p256PrivateKey, 32],
			self::CRV_P256K => [self::p256KPrivateKey, 32],
			self::CRV_P384  => [self::p384PrivateKey, 48],
			self::CRV_P521  => [self::p521PrivateKey, 66],
			default => throw new RuntimeException(sprintf('unsupported curve: "%s"', $jwk['crv'])),
		};

		$der  = sodium_hex2bin(sprintf($der, sodium_bin2hex($this->zeropad($key['d'], $padSize))));
		$der .= $this->getKey($jwk['crv'], $key['x'], $key['y']);

		return Util::formatPEM($der, 'EC PRIVATE');
	}

	public function publicKeyToPEM(array $jwk):string{

		if(!isset($jwk['crv'])){
			throw new InvalidArgumentException('"crv" not set');
		}

		$key = Util::filterKeyParams($jwk, self::PARAMS_PUBLIC);

		if(!isset($key['x'], $key['y'])){
			throw new InvalidArgumentException('"x" and/or "y" not set');
		}

		$der = match($jwk['crv']){
			self::CRV_P256  => self::p256PublicKey,
			self::CRV_P256K => self::p256KPublicKey,
			self::CRV_P384  => self::p384PublicKey,
			self::CRV_P521  => self::p521PublicKey,
			default => throw new RuntimeException(sprintf('unsupported curve: "%s"', $key['crv'])),
		};

		$der  = sodium_hex2bin($der);
		$der .= $this->getKey($jwk['crv'], $key['x'], $key['y']);

		return Util::formatPEM($der);
	}

	/**
	 * @see \openssl_pkey_get_private()
	 * @see \openssl_pkey_get_public()
	 */
	protected static function parseJWK(array $jsonKeyData):array{

		if(!isset($jsonKeyData['crv'])){
			throw new InvalidArgumentException('"crv" not set');
		}

		$ecKey   = new self;
		$public  = $ecKey->publicKeyToPEM($jsonKeyData);
		$private = null;

		if(isset($jsonKeyData['d'])){
			$private = $ecKey->privateKeyToPEM($jsonKeyData);
		}

		return [$private, $public];
	}

	protected function toArray(OpenSSLAsymmetricKey $key, bool $private, string|null $kid = null, string|null $use = null):array{
		$details = openssl_pkey_get_details($key);

		if($details === false){
			throw new RuntimeException('could not get key details'); // @codeCoverageIgnore
		}

		if($details['type'] !== OPENSSL_KEYTYPE_EC || !isset($details['ec']['curve_name'])){
			throw new InvalidArgumentException('the given key is not a valid EC key'); // @codeCoverageIgnore
		}

		if(!isset(self::EC_CURVES[$details['ec']['curve_name']])){
			throw new InvalidArgumentException('the given curve is not supported'); // @codeCoverageIgnore
		}

		$crv = self::EC_CURVES[$details['ec']['curve_name']];
		$jwk = $this->addInformationalValues(['kty' => 'EC', 'crv' => $crv], $kid, $use);

		$curveSize = $this->getNistCurveSize($crv);
		$params    = self::PARAMS_PUBLIC;

		if($private === true){
			$params = self::PARAMS_PRIVATE;
		}

		foreach($params as $param){
			if(isset($details['ec'][$param])){
				$jwk[$param] = Util::base64encode($this->zeropad($details['ec'][$param], $curveSize));
			}
		}

		return $jwk;
	}

	private function createKey(string $crv):OpenSSLAsymmetricKey{

		if(!isset(self::CRV_OPENSSL[$crv])){
			throw new InvalidArgumentException('the given curve is not supported'); // @codeCoverageIgnore
		}

		$key = openssl_pkey_new([
			'curve_name'       => self::CRV_OPENSSL[$crv],
			'private_key_type' => OPENSSL_KEYTYPE_EC,
		]);

		if($key === false){
			throw new RuntimeException('unable to create the key');
		}

		return $key;
	}

	private function getKey(string $crv, string $x, string $y):string{
		$curveSize = $this->getNistCurveSize($crv);

		return "\04".
			$this->zeropad(ltrim($x, "\x00"), $curveSize).
			$this->zeropad(ltrim($y, "\x00"), $curveSize);
	}

	private function getNistCurveSize(string $curve):int{

		$size = match($curve){
			self::CRV_P256, self::CRV_P256K => 256,
			self::CRV_P384                  => 384,
			self::CRV_P521                  => 521,
			default => throw new InvalidArgumentException('the given curve is not supported'), // @codeCoverageIgnore
		};

		return (int)ceil($size / 8);
	}

	private function zeropad(string $str, int $length):string{
		return str_pad($str, $length, "\x00", STR_PAD_LEFT);
	}

}
