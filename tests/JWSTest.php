<?php
/**
 * Class JWSTest
 *
 * @created      08.08.2024
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2024 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\JOSETest;

use chillerlan\JOSE\Algorithms\Signature\ECDSA;
use chillerlan\JOSE\Algorithms\Signature\EdDSA;
use chillerlan\JOSE\Algorithms\Signature\HMAC;
use chillerlan\JOSE\Algorithms\Signature\RSA;
use chillerlan\JOSE\Algorithms\Signature\RSAPSS;
use chillerlan\JOSE\Algorithms\Signature\SignatureAlgorithm;
use chillerlan\JOSE\JWS;
use chillerlan\JOSE\Key\ECKey;
use chillerlan\JOSE\Key\RSAKey;
use chillerlan\JOSE\Util;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function explode;
use function in_array;
use function random_bytes;
use const PHP_OS_FAMILY;
use const PHP_VERSION_ID;

/**
 * @link https://datatracker.ietf.org/doc/html/rfc7520
 * @link https://datatracker.ietf.org/doc/html/rfc8037
 */
final class JWSTest extends TestCase{

	protected function setUp():void{

		if(PHP_OS_FAMILY === 'Windows' && PHP_VERSION_ID < 80200){
			$this::markTestSkipped('PHP 8.1 under Windows might get hit with a bunch of OpenSSL errors');
		}

	}

	public static function algoProvider():array{
		return [
			// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.1
			'RFC7515-A1 (HS256)' => [
				'FQN'               => HMAC::class,
				'alg'               => 'HS256',
				'privateKey'        => RFC7515Examples::A1_JWK_SYMMETRIC,
				'publicKey'         => RFC7515Examples::A1_JWK_SYMMETRIC,
				'payloadString'     => Util::base64decode(RFC7515Examples::SIGN_PAYLOAD),
				'expectedHeader'    => RFC7515Examples::A1_EXPECTED_HEADER,
				'expectedSignature' => RFC7515Examples::A1_EXPECTED_SIGNATURE,
			],
			// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.2
			'RFC7515-A2 (RS256)'  => [
				'FQN'               => RSA::class,
				'alg'               => 'RS256',
				'privateKey'        => RFC7515Examples::A2_JWK_PRIVATE,
				'publicKey'         => RFC7515Examples::A2_JWK_PUBLIC,
				'payloadString'     => Util::base64decode(RFC7515Examples::SIGN_PAYLOAD),
				'expectedHeader'    => RFC7515Examples::A2_EXPECTED_HEADER,
				'expectedSignature' => RFC7515Examples::A2_EXPECTED_SIGNATURE,
			],
			// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.3
			'RFC7515-A3 (ES256)'  => [
				'FQN'               => ECDSA::class,
				'alg'               => 'ES256',
				'privateKey'        => RFC7515Examples::A3_JWK_PRIVATE,
				'publicKey'         => RFC7515Examples::A3_JWK_PUBLIC,
				'payloadString'     => Util::base64decode(RFC7515Examples::SIGN_PAYLOAD),
				'expectedHeader'    => RFC7515Examples::A3_EXPECTED_HEADER,
				'expectedSignature' => RFC7515Examples::A3_EXPECTED_SIGNATURE,
			],
			// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.4
			'RFC7515-A4 (ES512)'  => [
				'FQN'               => ECDSA::class,
				'alg'               => 'ES512',
				'privateKey'        => RFC7515Examples::A4_JWK_PRIVATE,
				'publicKey'         => RFC7515Examples::A4_JWK_PUBLIC,
				'payloadString'     => 'Payload',
				'expectedHeader'    => RFC7515Examples::A4_EXPECTED_HEADER,
				'expectedSignature' => RFC7515Examples::A4_EXPECTED_SIGNATURE,
			],
			// https://datatracker.ietf.org/doc/html/rfc7520#section-4.1
			'RFC7520-4.1 (RS256)' => [
				'FQN'               => RSA::class,
				'alg'               => 'RS256',
				'privateKey'        => RFC7520Examples::JWK_RSA_PRIVATE,
				'publicKey'         => RFC7520Examples::JWK_RSA_PUBLIC,
				'payloadString'     => RFC7520Examples::SIGN_PAYLOAD,
				'expectedHeader'    => RFC7520Examples::EX_41_EXPECTED_HEADER,
				'expectedSignature' => RFC7520Examples::EX_41_EXPECTED_SIGNATURE,

			],
			// https://datatracker.ietf.org/doc/html/rfc7520#section-4.2
			'RFC7520-4.2 (PS384)' => [
				'FQN'               => RSAPSS::class,
				'alg'               => 'PS384',
				'privateKey'        => RFC7520Examples::JWK_RSA_PRIVATE,
				'publicKey'         => RFC7520Examples::JWK_RSA_PUBLIC,
				'payloadString'     => RFC7520Examples::SIGN_PAYLOAD,
				'expectedHeader'    => RFC7520Examples::EX_42_EXPECTED_HEADER,
				'expectedSignature' => RFC7520Examples::EX_42_EXPECTED_SIGNATURE,

			],
			// https://datatracker.ietf.org/doc/html/rfc7520#section-4.3
			'RFC7520-4.3 (ES512)' => [
				'FQN'               => ECDSA::class,
				'alg'               => 'ES512',
				'privateKey'        => RFC7520Examples::JWK_EC_PRIVATE,
				'publicKey'         => RFC7520Examples::JWK_EC_PUBLIC,
				'payloadString'     => RFC7520Examples::SIGN_PAYLOAD,
				'expectedHeader'    => RFC7520Examples::EX_43_EXPECTED_HEADER,
				'expectedSignature' => RFC7520Examples::EX_43_EXPECTED_SIGNATURE,
			],
			// https://datatracker.ietf.org/doc/html/rfc7520#section-4.4
			'RFC7520-4.4 (HS256)' => [
				'FQN'               => HMAC::class,
				'alg'               => 'HS256',
				'privateKey'        => RFC7520Examples::JWK_SYMMETRIC,
				'publicKey'         => RFC7520Examples::JWK_SYMMETRIC,
				'payloadString'     => RFC7520Examples::SIGN_PAYLOAD,
				'expectedHeader'    => RFC7520Examples::EX_44_EXPECTED_HEADER,
				'expectedSignature' => RFC7520Examples::EX_44_EXPECTED_SIGNATURE,
			],
			// https://datatracker.ietf.org/doc/html/rfc8037#section-3.1
			'RFC8037-3.1 (EdDSA)' => [
				'FQN'               => EdDSA::class,
				'alg'               => 'EdDSA',
				'privateKey'        => RFC8037Examples::JWT_Ed25519_PRIVATE,
				'publicKey'         => RFC8037Examples::JWT_Ed25519_PUBLIC,
				'payloadString'     => RFC8037Examples::SIGN_PAYLOAD,
				'expectedHeader'    => RFC8037Examples::A4_EXPECTED_HEADER,
				'expectedSignature' => RFC8037Examples::A4_EXPECTED_SIGNATURE,
			],
		];
	}

	#[Test]
	#[DataProvider('algoProvider')]
	public function rfcSignExamples(
		string $FQN,
		string $alg,
		string $privateKey,
		string $publicKey,
		string $payloadString,
		string $expectedHeader,
		string $expectedSignature,
	):void{
		// extract the key from JSON
		$jwkPrivate = Util::parseJWK($privateKey);
		// init signature algo
		$signAlgo   = new $FQN($jwkPrivate, $alg);
		// init signature
		$jws        = new JWS($signAlgo);
		// sign with private key
		$jwt        = $jws->encode($payloadString, ['alg' => $alg], false);

		[$header, $payload, $signature] = explode('.', $jwt);

		$this::assertSame($expectedHeader, $header);
		$this::assertSame(Util::base64encode($payloadString), $payload);

		// EC type algorithm hashes are random
		if(!in_array($FQN, [ECDSA::class, RSAPSS::class], true)){
			$this::assertSame($expectedSignature, $signature);
		}

		// verify with public key parsed from a JWK string
		$jwkPublic  = Util::parseJWK($publicKey);
		$verifyAlgo = new $FQN($jwkPublic, $alg);

		$this::assertTrue($verifyAlgo->verify($header.'.'.$payload, Util::base64decode($expectedSignature)));
		// this covers the EC random hashes too
		$this::assertTrue($verifyAlgo->verify($header.'.'.$payload, Util::base64decode($signature)));

		$this::assertSame([Util::base64decode($expectedHeader), $payloadString], $jws->decode($jwt));
	}

	protected function assertSign(SignatureAlgorithm $signAlgo):void{
		$jws = new JWS($signAlgo);

		$expectedHeader     = ['typ' => 'JWT', 'alg' => $signAlgo->getName(), 'kid' => $signAlgo->getName().'-69420'];
		$expectedPayload    = ['foo' => 'bar'];
		$jwt                = $jws->encode($expectedPayload);
		[$header, $payload] = $jws->decode($jwt);

		$this::assertSame($expectedHeader,  Util::jsonDecode($header));
		$this::assertSame($expectedPayload, Util::jsonDecode($payload));
	}

	public static function ECDSAalgoProvider():array{
		return [
			'ES256'  => ['ES256' , 'P-256' ],
			'ES256K' => ['ES256K', 'P-256K'],
			'ES384'  => ['ES384' , 'P-384' ],
			'ES512'  => ['ES512' , 'P-521' ],
		];
	}

	#[Test]
	#[DataProvider('ECDSAalgoProvider')]
	public function ECDSAsign(string $algo, string $crv):void{
		$privateKey = (new ECKey)->create(kid: $algo.'-69420', use: 'sign', crv: $crv);
		$jwkPrivate = Util::parseJWK($privateKey);
		$signAlgo   = new ECDSA($jwkPrivate, $algo);

		$this->assertSign($signAlgo);
	}

	public static function RSAalgoProvider():array{
		return [
			'RS256' => ['RS256' , 2048],
			'RS384' => ['RS384' , 3072],
			'RS512' => ['RS512' , 4096],
		];
	}

	#[Test]
	#[DataProvider('RSAalgoProvider')]
	public function RSAsign(string $algo, int $keylength):void{
		$privateKey = (new RSAKey)->create(kid: $algo.'-69420', use: 'sign', size: $keylength);
		$jwkPrivate = Util::parseJWK($privateKey);
		$signAlgo   = new RSA($jwkPrivate, $algo);

		$this->assertSign($signAlgo);
	}

	public static function RSAPSSalgoProvider():array{
		return [
			'PS256' => ['PS256' , 2048],
			'PS384' => ['PS384' , 3072],
			'PS512' => ['PS512' , 4096],
		];
	}

	#[Test]
	#[DataProvider('RSAPSSalgoProvider')]
	public function RSAPSSsign(string $algo, int $keylength):void{
		$privateKey = (new RSAKey)->create(kid: $algo.'-69420', use: 'sign', size: $keylength);
		$jwkPrivate = Util::parseJWK($privateKey);
		$signAlgo   = new RSAPSS($jwkPrivate, $algo);

		$this->assertSign($signAlgo);
	}

	public static function HMACalgoProvider():array{
		return [
			'HS256' => ['HS256' , 32],
			'HS384' => ['HS384' , 48],
			'HS512' => ['HS512' , 64],
		];
	}

	#[Test]
	#[DataProvider('HMACalgoProvider')]
	public function HMACsign(string $algo, int $keylength):void{

		$key = [
			'kty' => 'oct',
			'kid' => $algo.'-69420',
			'use' => 'sign',
			'k'   => Util::base64encode(random_bytes($keylength)),
		];

		$privateKey = Util::jsonEncode($key);
		$jwkPrivate = Util::parseJWK($privateKey);
		$signAlgo   = new HMAC($jwkPrivate, $algo);

		$this->assertSign($signAlgo);
	}

}
