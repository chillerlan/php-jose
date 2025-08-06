<?php
/**
 * KeyManager.php
 *
 * @created      19.08.2024
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2024 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\JOSE\Key;

interface OpenSSLKey extends JWK{

	public function privateKeyToPEM(array $key):string;

	public function publicKeyToPEM(array $key):string;

	public function pemToPrivateJWK(string $pem, string|null $kid = null, string|null $use = null):string;

	public function pemToPublicJWK(string $pem, string|null $kid = null, string|null $use = null):string;

}
