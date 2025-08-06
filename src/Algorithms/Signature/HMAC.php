<?php
/**
 * Class HMAC
 *
 * @created      08.08.2024
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2024 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\JOSE\Algorithms\Signature;

use chillerlan\JOSE\Algorithms\JWAAbstract;
use RuntimeException;
use Throwable;
use function hash_equals;
use function hash_hmac;
use function strlen;

/**
 * HMAC Signature Algorithm
 *
 * @link https://datatracker.ietf.org/doc/html/rfc7518#section-3.2
 * @link https://datatracker.ietf.org/doc/html/rfc7520#section-4.4
 */
final class HMAC extends JWAAbstract implements SignatureAlgorithm{

	public const SUPPORTED_ALGOS = [
		'HS256' => 'SHA256', // required
		'HS384' => 'SHA384',
		'HS512' => 'SHA512',
	];

	private const MIN_KEYLENGTH = [
		'HS256' => 256,
		'HS384' => 384,
		'HS512' => 512,
	];

	public function sign(string $message):string{
		return $this->hash($message);
	}

	public function verify(string $message, string $signature):bool{
		return hash_equals($this->hash($message), $signature);
	}

	private function hash(string $message):string{
		return hash_hmac($this::SUPPORTED_ALGOS[$this->algo], $message, $this->getHmacKey(), true);
	}

	private function getHmacKey():string{

		// the key is symmetric and may be set as either private or publc
		try{
			$key = $this->jwk->getPrivateKey();
		}
		catch(Throwable){
			$key = $this->jwk->getPublicKey();
		}

		if((strlen($key) * 8) < $this::MIN_KEYLENGTH[$this->algo]){
			throw new RuntimeException('the given key is too short');
		}

		return $key;
	}

}
