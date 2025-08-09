<?php
/**
 * Class OKPKeyTest
 *
 * @created      07.08.2025
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2025 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\JOSETest\Key;

use chillerlan\JOSE\Key\JWK;
use chillerlan\JOSE\Key\OKPKey;
use chillerlan\JOSETest\RFC8037Examples;

class OKPKeyTest extends KeyTestAbstract{

	protected const TEST_JWK_PRIVATE = RFC8037Examples::JWT_Ed25519_PRIVATE;
	protected const TEST_JWK_PUBLIC  = RFC8037Examples::JWT_Ed25519_PUBLIC;

	protected function invokeJWK():JWK{
		return new OKPKey;
	}

}
