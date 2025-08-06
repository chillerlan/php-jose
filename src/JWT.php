<?php
/**
 * Interface JWT
 *
 * @created      17.08.2024
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2024 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\JOSE;

/**
 * JSON Web Token (JWT)
 *
 * @link https://datatracker.ietf.org/doc/html/rfc7519
 * @link https://datatracker.ietf.org/doc/html/rfc7520
 * @link https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid
 * @link https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
 */
interface JWT{

	public function encode(object|array|string $payload, array|null $headers = null, bool|null $jsonEncodeString = null):string;
	public function decode(string $jwt):array;

}
