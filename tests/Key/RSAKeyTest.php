<?php
/**
 * Class RSAKeyTest
 *
 * @created      13.08.2024
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2024 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\JOSETest\Key;

use chillerlan\JOSE\Key\RSAKey;
use chillerlan\JOSE\Util;
use chillerlan\JOSETest\RFC7520Examples;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function array_flip;
use function array_intersect_key;
use function array_map;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use const PHP_OS_FAMILY;
use const PHP_VERSION_ID;

class RSAKeyTest extends TestCase{

	protected function setUp():void{

		if(PHP_OS_FAMILY === 'Windows' && PHP_VERSION_ID < 80200){
			$this::markTestSkipped('PHP 8.1 under Windows might get hit with a bunch of OpenSSL errors');
		}
	}

	#[Test]
	public function pemFromKeyParams():void{
		$jwk = Util::jsonDecode(RFC7520Examples::JWK_RSA_PRIVATE);
		$key   = array_intersect_key($jwk, array_flip(RSAKey::PARAMS_PRIVATE));

		$rsaKey     = new RSAKey;
		$pemPublic  = $rsaKey->publicKeyToPEM($key);
		$pemPrivate = $rsaKey->privateKeyToPEM($key);

		$this::assertSame(RFC7520Examples::PEM_RSA_PUBLIC, $pemPublic);
		$this::assertSame(RFC7520Examples::PEM_RSA_PRIVATE, $pemPrivate);

		$pkey = openssl_pkey_get_private($pemPrivate);

		$this::assertInstanceOf(OpenSSLAsymmetricKey::class, $pkey);

		$details = openssl_pkey_get_details($pkey);

		$this::assertIsArray($details);
		$this::assertArrayHasKey('rsa', $details);

		$key = array_map(Util::base64decode(...), $key);

		foreach(RSAKey::PARAMS_PRIVATE as $j => $o){
			$this::assertSame($key[$o], $details['rsa'][RSAKey::PARAMS_OPENSSL[$j]]);
		}

	}

	#[Test]
	public function pemFromKeyParamsWithoutAllPrimes():void{
		$jwk = Util::jsonDecode(RFC7520Examples::JWK_RSA_PRIVATE);
		$k   = array_intersect_key($jwk, array_flip(RSAKey::PARAMS_PRIVATE));

		unset($k['dp'], $k['dq'], $k['qi']);

		$rsaKey     = new RSAKey;
		$pemPublic  = $rsaKey->publicKeyToPEM($k);
		$pemPrivate = $rsaKey->privateKeyToPEM($k);

		$this::assertSame(RFC7520Examples::PEM_RSA_PUBLIC, $pemPublic);
		$this::assertSame(RFC7520Examples::PEM_RSA_PRIVATE, $pemPrivate);

		$key = openssl_pkey_get_private($pemPrivate);

		$this::assertInstanceOf(OpenSSLAsymmetricKey::class, $key);

		$details = openssl_pkey_get_details($key);

		$this::assertIsArray($details);
		$this::assertArrayHasKey('rsa', $details);

		$k = array_map(Util::base64decode(...), $k);

		foreach($k as $j => $o){
			$this::assertSame($o, $details['rsa'][$j]);
		}

	}

	#[Test]
	public function pemFromKeyPublicParams():void{
		$jwk = Util::jsonDecode(RFC7520Examples::JWK_RSA_PUBLIC);
		$k   = array_intersect_key($jwk, array_flip(RSAKey::PARAMS_PUBLIC));

		$rsaKey     = new RSAKey;
		$pemPublic  = $rsaKey->publicKeyToPEM($k);

		$this::assertSame(RFC7520Examples::PEM_RSA_PUBLIC, $pemPublic);

		$key = openssl_pkey_get_public($pemPublic);

		$this::assertInstanceOf(OpenSSLAsymmetricKey::class, $key);

		$details = openssl_pkey_get_details($key);

		$this::assertIsArray($details);
		$this::assertArrayHasKey('rsa', $details);

		$k = array_map(Util::base64decode(...), $k);

		foreach($k as $j => $o){
			$this::assertSame($o, $details['rsa'][$j]);
		}

	}

}
