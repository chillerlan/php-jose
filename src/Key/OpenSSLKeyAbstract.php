<?php
/**
 * Class OpenSSLAbstract
 *
 * @created      07.08.2025
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2025 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\JOSE\Key;

use chillerlan\JOSE\Util;
use OpenSSLAsymmetricKey;

abstract class OpenSSLKeyAbstract extends JWKAbstract implements OpenSSLKey{

	abstract protected function toArray(
		OpenSSLAsymmetricKey $key,
		bool                 $private,
		string|null          $kid = null,
		string|null          $use = null,
	):array;

	public function pemToPrivateJWK(string $pem, string|null $kid = null, string|null $use = null):array{
		return $this->toArray(Util::loadPEM($pem), true, $kid, $use);
	}

	public function pemToPublicJWK(string $pem, string|null $kid = null, string|null $use = null):array{
		return $this->toArray(Util::loadPEM($pem), false, $kid, $use);
	}

	public function toPrivateJWK(string|null $kid = null, string|null $use = null):array{
		return $this->pemToPrivateJWK($this->getPrivateKey(), $kid, $use);
	}

	public function toPublicJWK(string|null $kid = null, string|null $use = null):array{
		return $this->pemToPublicJWK($this->getPublicKey(), $kid, $use);
	}

}
