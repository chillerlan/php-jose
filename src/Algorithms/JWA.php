<?php
/**
 * Class JWA
 *
 * @created      05.08.2024
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2024 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\JOSE\Algorithms;

use chillerlan\JOSE\Key\JWK;

/**
 * JSON Web Algorithms (JWA)
 *
 * @link https://datatracker.ietf.org/doc/html/rfc7518
 * @link https://datatracker.ietf.org/doc/html/rfc8037
 */
interface JWA{

	public const SUPPORTED_ALGOS = [];

	public function isSupported(string $algo):bool;
	public function getJwk():JWK;
	public function getName():string;

}
