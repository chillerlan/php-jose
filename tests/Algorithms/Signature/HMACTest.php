<?php
/**
 * Class HMACTest
 *
 * @created      09.08.2025
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2025 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\JOSETest\Algorithms\Signature;

use chillerlan\JOSE\Algorithms\Signature\HMAC;
use chillerlan\JOSE\Util;
use chillerlan\JOSETest\RFC7515Examples;
use chillerlan\JOSETest\RFC7520Examples;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function random_bytes;

final class HMACTest extends SignatureAlgoTestAbstract{

	protected const FQN = HMAC::class;

	public static function algoProvider():array{
		return [
			// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.1
			'RFC7515-A1 (HS256)' => [
				'alg'               => HMAC::ALGO_HS256,
				'privateKey'        => RFC7515Examples::A1_JWK_SYMMETRIC,
				'publicKey'         => RFC7515Examples::A1_JWK_SYMMETRIC,
				'payloadString'     => Util::base64decode(RFC7515Examples::SIGN_PAYLOAD),
				'expectedHeader'    => RFC7515Examples::A1_EXPECTED_HEADER,
				'expectedSignature' => RFC7515Examples::A1_EXPECTED_SIGNATURE,
			],
			// https://datatracker.ietf.org/doc/html/rfc7520#section-4.4
			'RFC7520-4.4 (HS256)' => [
				'alg'               => HMAC::ALGO_HS256,
				'privateKey'        => RFC7520Examples::JWK_SYMMETRIC,
				'publicKey'         => RFC7520Examples::JWK_SYMMETRIC,
				'payloadString'     => RFC7520Examples::SIGN_PAYLOAD,
				'expectedHeader'    => RFC7520Examples::EX_44_EXPECTED_HEADER,
				'expectedSignature' => RFC7520Examples::EX_44_EXPECTED_SIGNATURE,
			],
		];
	}

	public static function HMACalgoProvider():array{
		return [
			HMAC::ALGO_HS256 => [HMAC::ALGO_HS256, 32],
			HMAC::ALGO_HS384 => [HMAC::ALGO_HS384, 48],
			HMAC::ALGO_HS512 => [HMAC::ALGO_HS512, 64],
		];
	}

	#[Test]
	#[DataProvider('HMACalgoProvider')]
	public function HMACsign(string $algo, int $keylength):void{

		$key = [
			'kty' => 'oct',
			'kid' => $this::KID,
			'k'   => Util::base64encode(random_bytes($keylength)),
		];

		$privateKey = Util::jsonEncode($key);
		$jwkPrivate = Util::parseJWK($privateKey);
		$signAlgo   = new HMAC($jwkPrivate, $algo);

		$this->assertSign($signAlgo);
	}

}
