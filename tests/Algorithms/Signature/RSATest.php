<?php
/**
 * Class RSATest
 *
 * @created      09.08.2025
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2025 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\JOSETest\Algorithms\Signature;

use chillerlan\JOSE\Algorithms\Signature\RSA;
use chillerlan\JOSE\Key\RSAKey;
use chillerlan\JOSE\Util;
use chillerlan\JOSETest\RFC7515Examples;
use chillerlan\JOSETest\RFC7520Examples;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

final class RSATest extends SignatureAlgoTestAbstract{

	protected const FQN = RSA::class;

	public static function algoProvider():array{
		return [
			// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.2
			'RFC7515-A2 (RS256)'  => [
				'alg'               => RSA::ALGO_RS256,
				'privateKey'        => RFC7515Examples::A2_JWK_PRIVATE,
				'publicKey'         => RFC7515Examples::A2_JWK_PUBLIC,
				'payloadString'     => Util::base64decode(RFC7515Examples::SIGN_PAYLOAD),
				'expectedHeader'    => RFC7515Examples::A2_EXPECTED_HEADER,
				'expectedSignature' => RFC7515Examples::A2_EXPECTED_SIGNATURE,
			],
			// https://datatracker.ietf.org/doc/html/rfc7520#section-4.1
			'RFC7520-4.1 (RS256)' => [
				'alg'               => RSA::ALGO_RS256,
				'privateKey'        => RFC7520Examples::JWK_RSA_PRIVATE,
				'publicKey'         => RFC7520Examples::JWK_RSA_PUBLIC,
				'payloadString'     => RFC7520Examples::SIGN_PAYLOAD,
				'expectedHeader'    => RFC7520Examples::EX_41_EXPECTED_HEADER,
				'expectedSignature' => RFC7520Examples::EX_41_EXPECTED_SIGNATURE,

			],
		];
	}

	public static function RSAalgoProvider():array{
		return [
			RSA::ALGO_RS256 => [RSA::ALGO_RS256, 2048],
			RSA::ALGO_RS384 => [RSA::ALGO_RS384, 3072],
			RSA::ALGO_RS512 => [RSA::ALGO_RS512, 4096],
		];
	}

	#[Test]
	#[DataProvider('RSAalgoProvider')]
	public function RSAsign(string $algo, int $keylength):void{
		$privateKey = (new RSAKey)->create(kid: $this::KID, size: $keylength);
		$jwkPrivate = Util::parseJWK($privateKey);
		$signAlgo   = new RSA($jwkPrivate, $algo);

		$this->assertSign($signAlgo);
	}

}
