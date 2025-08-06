<?php
/**
 * Interface SignatureAlgorithm
 *
 * @created      08.08.2024
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2024 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\JOSE\Algorithms\Signature;

use chillerlan\JOSE\Algorithms\JWA;

/**
 * @link https://datatracker.ietf.org/doc/html/rfc7518#section-3
 */
interface SignatureAlgorithm extends JWA{

	/**
	 * Signs the given message with the given key and algorithm
	 */
	public function sign(string $message):string;

	public function verify(string $message, string $signature):bool;

}
