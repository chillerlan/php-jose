<?php
/**
 * Class ECKeyTest
 *
 * @created      13.08.2024
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2024 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\JOSETest\Key;

use chillerlan\JOSE\Key\ECKey;
use chillerlan\JOSE\Key\JWK;
use chillerlan\JOSE\Util;
use chillerlan\JOSETest\RFC7520Examples;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\Test;
use function json_decode;
use function ltrim;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;

class ECKeyTest extends KeyTestAbstract{

	protected const TEST_JWK_PRIVATE = RFC7520Examples::JWK_EC_PRIVATE;
	protected const TEST_JWK_PUBLIC  = RFC7520Examples::JWK_EC_PUBLIC;

	protected function invokeJWK():JWK{
		return new ECKey;
	}

	#[Test]
	public function pemFromJwk():void{
		$jwk        = Util::jsonDecode(RFC7520Examples::JWK_EC_PRIVATE);
		$ecKey      = new ECKey;
		$pemPublic  = $ecKey->publicKeyToPEM($jwk);
		$pemPrivate = $ecKey->privateKeyToPEM($jwk);

		$this::assertSame(RFC7520Examples::PEM_EC_PUBLIC, $pemPublic);
		$this::assertSame(RFC7520Examples::PEM_EC_PRIVATE, $pemPrivate);

		$key = openssl_pkey_get_private($pemPrivate);

		$this::assertInstanceOf(OpenSSLAsymmetricKey::class, $key);

		$details = openssl_pkey_get_details($key);

		$this::assertIsArray($details);
		$this::assertArrayHasKey('ec', $details);

		foreach(ECKey::PARAMS_PRIVATE as $param){
			// the decoded binary strings from the RFC examples are prepended with a NUL byte
			$expected = ltrim(Util::base64decode($jwk[$param]), "\x0");

			$this::assertSame($expected, $details['ec'][$param]);
		}

	}

	#[Test]
	public function pemToJwk():void{
		$private = (new ECKey)->pemToPrivateJWK(RFC7520Examples::PEM_EC_PRIVATE, 'bilbo.baggins@hobbiton.example', 'sig');
		$this::assertSame(json_decode(RFC7520Examples::JWK_EC_PRIVATE, true), $private);

		$public = (new ECKey)->pemToPublicJWK(RFC7520Examples::PEM_EC_PUBLIC, 'bilbo.baggins@hobbiton.example', 'sig');
		$this::assertSame(json_decode(RFC7520Examples::JWK_EC_PUBLIC, true), $public);
	}

}
