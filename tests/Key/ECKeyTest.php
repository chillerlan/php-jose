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
use chillerlan\JOSE\Util;
use chillerlan\JOSETest\RFC7520Examples;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function array_flip;
use function array_intersect_key;
use function array_map;
use function json_decode;
use function ltrim;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;

class ECKeyTest extends TestCase{

	#[Test]
	public function pemFromKeyParams():void{
		$jwk = Util::jsonDecode(RFC7520Examples::JWK_EC_PRIVATE);
		$k   = array_intersect_key($jwk, array_flip(ECKey::PARAMS_PRIVATE));

		$ecKey      = new ECKey;
		$pemPublic  = $ecKey->publicKeyToPEM($k, $jwk['crv']);
		$pemPrivate = $ecKey->privateKeyToPEM($k, $jwk['crv']);

		$this::assertSame(RFC7520Examples::PEM_EC_PUBLIC, $pemPublic);
		$this::assertSame(RFC7520Examples::PEM_EC_PRIVATE, $pemPrivate);

		$key = openssl_pkey_get_private($pemPrivate);

		$this::assertInstanceOf(OpenSSLAsymmetricKey::class, $key);

		$details = openssl_pkey_get_details($key);

		$this::assertIsArray($details);
		$this::assertArrayHasKey('ec', $details);

		// the decoded binary strings from the RFC examples are prepended with a NUL byte
		$k = array_map(fn(string $v):string => ltrim(Util::base64decode($v), "\x0"), $k);

		foreach(ECKey::PARAMS_PRIVATE as $param){
			$this::assertSame($k[$param], $details['ec'][$param]);
		}

	}

	#[Test]
	public function pemToJWK():void{
		$private = (new ECKey)->pemToPrivateJWK(RFC7520Examples::PEM_EC_PRIVATE, 'bilbo.baggins@hobbiton.example', 'sig');
		$this::assertSame(json_decode(RFC7520Examples::JWK_EC_PRIVATE, true), json_decode($private, true));

		$public = (new ECKey)->pemToPublicJWK(RFC7520Examples::PEM_EC_PUBLIC, 'bilbo.baggins@hobbiton.example', 'sig');
		$this::assertSame(json_decode(RFC7520Examples::JWK_EC_PUBLIC, true), json_decode($public, true));
	}

}
