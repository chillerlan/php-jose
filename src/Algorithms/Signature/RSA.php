<?php
/**
 * Class RSA
 *
 * @created      10.08.2024
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2024 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\JOSE\Algorithms\Signature;

use chillerlan\JOSE\Algorithms\OpenSSLAbstract;
use const OPENSSL_ALGO_SHA256;
use const OPENSSL_ALGO_SHA384;
use const OPENSSL_ALGO_SHA512;
use const OPENSSL_KEYTYPE_RSA;

/**
 * RSA Signature Algorithm
 *
 * @link https://datatracker.ietf.org/doc/html/rfc7518#section-3.3
 * @link https://datatracker.ietf.org/doc/html/rfc7520#section-4.1
 */
final class RSA extends OpenSSLAbstract implements SignatureAlgorithm{

	public const SUPPORTED_ALGOS = [
		'RS256' => OPENSSL_ALGO_SHA256,
		'RS384' => OPENSSL_ALGO_SHA384,
		'RS512' => OPENSSL_ALGO_SHA512,
	];

	protected const KEYTYPE = OPENSSL_KEYTYPE_RSA;

	public function sign(string $message):string{
		return $this->signMessage($message);
	}

	public function verify(string $message, string $signature):bool{
		return $this->verifySignature($message, $signature);
	}

	protected function checkKeyLength(int $bits):bool{
		return $bits >= 2048;
	}

}
