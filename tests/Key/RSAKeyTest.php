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

use chillerlan\JOSE\Key\JWK;
use chillerlan\JOSE\Key\RSAKey;
use chillerlan\JOSE\Util;
use chillerlan\JOSETest\RFC7520Examples;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\Test;
use function array_combine;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use const PHP_OS_FAMILY;
use const PHP_VERSION_ID;

class RSAKeyTest extends KeyTestAbstract{

	protected const TEST_JWK_PRIVATE = RFC7520Examples::JWK_RSA_PRIVATE;
	protected const TEST_JWK_PUBLIC  = RFC7520Examples::JWK_RSA_PUBLIC;

	protected function setUp():void{

		if(PHP_OS_FAMILY === 'Windows' && PHP_VERSION_ID < 80200){
			$this::markTestSkipped('PHP 8.1 under Windows might get hit with a bunch of OpenSSL errors');
		}

		parent::setUp();
	}

	protected function invokeJWK():JWK{
		return new RSAKey;
	}

	#[Test]
	public function pemFromJwk():void{
		$jwk        = Util::jsonDecode(RFC7520Examples::JWK_RSA_PRIVATE);
		$rsaKey     = new RSAKey;
		$pemPublic  = $rsaKey->publicKeyToPEM($jwk);
		$pemPrivate = $rsaKey->privateKeyToPEM($jwk);

		$this::assertSame(RFC7520Examples::PEM_RSA_PUBLIC, $pemPublic);
		$this::assertSame(RFC7520Examples::PEM_RSA_PRIVATE, $pemPrivate);

		$pkey = openssl_pkey_get_private($pemPrivate);

		$this::assertInstanceOf(OpenSSLAsymmetricKey::class, $pkey);

		$details = openssl_pkey_get_details($pkey);

		$this::assertIsArray($details);
		$this::assertArrayHasKey('rsa', $details);

		foreach(array_combine(RSAKey::PARAMS_PRIVATE, RSAKey::PARAMS_OPENSSL) as $p => $o){
			$expected = Util::base64decode($jwk[$p]);

			$this::assertSame($expected, $details['rsa'][$o]);
		}

	}

	#[Test]
	public function pemFromJwkWithoutAllPrimes():void{
		$jwk = Util::jsonDecode(RFC7520Examples::JWK_RSA_PRIVATE);

		unset($jwk['dp'], $jwk['dq'], $jwk['qi']);

		foreach(['dp', 'dq', 'qi'] as $o){
			$this::assertArrayNotHasKey($o, $jwk);
		}

		$rsaKey     = new RSAKey;
		$pemPublic  = $rsaKey->publicKeyToPEM($jwk);
		$pemPrivate = $rsaKey->privateKeyToPEM($jwk);

		$this::assertSame(RFC7520Examples::PEM_RSA_PUBLIC, $pemPublic);
		$this::assertSame(RFC7520Examples::PEM_RSA_PRIVATE, $pemPrivate);

		$key = openssl_pkey_get_private($pemPrivate);

		$this::assertInstanceOf(OpenSSLAsymmetricKey::class, $key);

		$details = openssl_pkey_get_details($key);

		$this::assertIsArray($details);
		$this::assertArrayHasKey('rsa', $details);

		foreach(['dmp1', 'dmq1', 'iqmp'] as $o){
			$this::assertArrayNotHasKey($o, $details);
		}

		foreach(['n', 'e', 'd', 'p', 'q'] as $p){
			$expected = Util::base64decode($jwk[$p]);

			$this::assertSame($expected, $details['rsa'][$p]);
		}

	}

	#[Test]
	public function pemFromPublicJwk():void{
		$jwk       = Util::jsonDecode(RFC7520Examples::JWK_RSA_PUBLIC);
		$rsaKey    = new RSAKey;
		$pemPublic = $rsaKey->publicKeyToPEM($jwk);

		$this::assertSame(RFC7520Examples::PEM_RSA_PUBLIC, $pemPublic);

		$key = openssl_pkey_get_public($pemPublic);

		$this::assertInstanceOf(OpenSSLAsymmetricKey::class, $key);

		$details = openssl_pkey_get_details($key);

		$this::assertIsArray($details);
		$this::assertArrayHasKey('rsa', $details);

		foreach(RSAKey::PARAMS_PUBLIC as $p){
			$expected = Util::base64decode($jwk[$p]);

			$this::assertSame($expected, $details['rsa'][$p]);
		}

	}

}
