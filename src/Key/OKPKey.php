<?php
/**
 * Class OKPKey
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
use function in_array;
use function sodium_crypto_sign_keypair;
use function sodium_crypto_sign_publickey;
use function sodium_crypto_sign_secretkey;
use function substr;
use function trim;

/**
 * ECDH-ES Key
 *
 * @link https://datatracker.ietf.org/doc/html/rfc8037#section-3.2
 *
 * @see \chillerlan\JOSE\Algorithms\Signature\EdDSA
 */
final class OKPKey extends JWKAbstract{

	public const KTY = 'OKP';

	private const KEY_PARAMS = ['x', 'd'];

	// supported "crv" values for "OKP" type, see https://datatracker.ietf.org/doc/html/rfc8037#section-3.1
	private const SUBTYPES = ['Ed25519'];

	/**
	 * @see \sodium_crypto_sign_keypair()
	 */
	protected static function parseJWK(array $jsonKeyData):array{

		if(!isset($jsonKeyData['crv'])){
			throw new RuntimeException('"crv" not set');
		}

		if(!in_array($jsonKeyData['crv'], self::SUBTYPES, true)){
			throw new RuntimeException('unsupported OKP subtype');
		}

		if(!isset($jsonKeyData['x'])){
			throw new RuntimeException('public key "x" not set');
		}

		$key     = Util::parseKeyParams($jsonKeyData, self::KEY_PARAMS);
		$private = null;

		if(isset($key['d'])){
			// @todo in case more OKP subtypes are added
			// sodium_crypto_sign private keys are (private + public)
			// we're going to concatenate the keys here as there's currently only one supported algo anyways
			$private = $key['d'].$key['x']; // SODIUM_CRYPTO_SIGN_SECRETKEYBYTES = 64
		}

		return [$private, $key['x']];
	}

	public function create(string|null $kid = null, string|null $use = null, bool $asPEM = false):string{

		if($asPEM === true){
			throw new RuntimeException('PEM export is not supported');
		}

		$sign_pair = sodium_crypto_sign_keypair();

		$jwk = [
			'kty' => 'OKP',
			'alg' => 'EdDSA',
			'crv' => 'Ed25519',
			'd'   => Util::base64encode(substr(sodium_crypto_sign_secretkey($sign_pair), 0, 32)),
			'x'   => Util::base64encode(sodium_crypto_sign_publickey($sign_pair)),
		];

		foreach(['kid' => $kid, 'use' => $use] as $var => $val){
			if($val !== null){
				$jwk[$var] = trim($val);
			}
		}

		return Util::jsonEncode($jwk);
	}

}
