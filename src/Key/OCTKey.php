<?php
/**
 * Class OCTKey
 *
 * @created      29.11.2024
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2024 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\JOSE\Key;

use chillerlan\JOSE\Util;
use RuntimeException;
use function random_bytes;

/**
 * Symmetric Key
 *
 * @link https://datatracker.ietf.org/doc/html/rfc7518#section-6.4
 *
 * @see \chillerlan\JOSE\Algorithms\Signature\HMAC
 */
final class OCTKey extends JWKAbstract{

	public const KTY = 'oct';

	public const PARAMS_PRIVATE = ['k'];
	public const PARAMS_PUBLIC  = ['k'];

	/**
	 * @see \hash_hmac()
	 */
	protected static function parseJWK(array $jsonKeyData):array{

		if(!isset($jsonKeyData['k'])){
			throw new RuntimeException('octet sequence "k" not set');
		}

		// the key is a symmetric key, we're going to use it as public and private here
		$key = Util::base64decode($jsonKeyData['k']);

		return [$key, $key];
	}

	public function create(string|null $kid = null, string|null $use = null, bool $asPEM = false):array{

		if($asPEM === true){
			throw new RuntimeException('PEM export is not supported');
		}

		$jwk = [
			'kty' => 'oct',
			'k'   => Util::base64encode(random_bytes(64)),
		];

		return $this->addInformationalValues($jwk, $kid, $use);
	}

	public function toPrivateJWK(string|null $kid = null, string|null $use = null):array{

		$jwk = [
			'kty' => 'oct',
			'k'   => Util::base64encode($this->getPrivateKey()),
		];

		return $this->addInformationalValues($jwk, $kid, $use);
	}

	public function toPublicJWK(string|null $kid = null, string|null $use = null):array{

		$jwk = [
			'kty' => 'oct',
			'k'   => Util::base64encode($this->getPublicKey()),
		];

		return $this->addInformationalValues($jwk, $kid, $use);
	}

}
