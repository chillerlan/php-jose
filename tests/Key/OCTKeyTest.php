<?php
/**
 * Class OCTKeyTest
 *
 * @created      07.08.2025
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2025 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\JOSETest\Key;

use chillerlan\JOSE\Key\JWK;
use chillerlan\JOSE\Key\OCTKey;
use chillerlan\JOSETest\RFC7515Examples;

class OCTKeyTest extends KeyTestAbstract{

	protected const TEST_JWK_PRIVATE = RFC7515Examples::A1_JWK_SYMMETRIC;
	protected const TEST_JWK_PUBLIC  = RFC7515Examples::A1_JWK_SYMMETRIC;

	protected function invokeJWK():JWK{
		return new OCTKey;
	}

}
