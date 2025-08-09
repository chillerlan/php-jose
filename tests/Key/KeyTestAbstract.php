<?php
/**
 * Class KeyTestAbstract
 *
 * @created      07.08.2025
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2025 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\JOSETest\Key;

use chillerlan\JOSE\Key\JWK;
use chillerlan\JOSE\Util;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

abstract class KeyTestAbstract extends TestCase{

	protected const TEST_JWK_PRIVATE = '';
	protected const TEST_JWK_PUBLIC  = '';

	protected JWK $jwk;

	protected function setUp():void{
		$this->jwk = $this->invokeJWK();
	}

	abstract protected function invokeJWK():JWK;

	#[Test]
	public function toPrivateJWK():void{
		$jwk      = $this->jwk::parse(Util::jsonDecode(static::TEST_JWK_PRIVATE))->toPrivateJWK();
		$expected = Util::jsonDecode(static::TEST_JWK_PRIVATE);

		foreach($expected as $k => $v){
			$this::assertSame($v, $jwk[$k]);
		}

	}

	#[Test]
	public function toPublicJWK():void{
		$jwk      = $this->jwk::parse(Util::jsonDecode(static::TEST_JWK_PUBLIC))->toPublicJWK();
		$expected = Util::jsonDecode(static::TEST_JWK_PUBLIC);

		foreach($expected as $k => $v){
			$this::assertSame($v, $jwk[$k]);
		}

	}

}
