<?php
/**
 * Class Sodium
 *
 * @created      08.08.2024
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2024 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\JOSE\Algorithms\Signature;

use chillerlan\JOSE\Algorithms\JWAAbstract;
use function sodium_crypto_sign_detached;
use function sodium_crypto_sign_verify_detached;

/**
 * EdDSA Signature Algorithm
 *
 * @link https://datatracker.ietf.org/doc/html/rfc8037#section-3.1
 */
final class EdDSA extends JWAAbstract implements SignatureAlgorithm{

	public const ALGO_EDDSA = 'EdDSA';

	public const SUPPORTED_ALGOS = [
		self::ALGO_EDDSA => 'Ed25519',
	];

	public function sign(string $message):string{
		return sodium_crypto_sign_detached($message, $this->jwk->getPrivateKey());
	}

	public function verify(string $message, string $signature):bool{
		return sodium_crypto_sign_verify_detached($signature, $message, $this->jwk->getPublicKey());
	}

}
