<?php
/**
 * Class RSAPSSTest
 *
 * @created      09.08.2025
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2025 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\JOSETest\Algorithms\Signature;

use chillerlan\JOSE\Algorithms\Signature\RSAPSS;
use chillerlan\JOSE\Key\RSAKey;
use chillerlan\JOSE\Util;
use chillerlan\JOSETest\RFC7520Examples;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

final class RSAPSSTest extends SignatureAlgoTestAbstract{

	protected const FQN = RSAPSS::class;

	public static function algoProvider():array{
		return [
			// https://datatracker.ietf.org/doc/html/rfc7520#section-4.2
			'RFC7520-4.2 (PS384)' => [
				'alg'               => RSAPSS::ALGO_PS384,
				'privateKey'        => RFC7520Examples::JWK_RSA_PRIVATE,
				'publicKey'         => RFC7520Examples::JWK_RSA_PUBLIC,
				'payloadString'     => RFC7520Examples::SIGN_PAYLOAD,
				'expectedHeader'    => RFC7520Examples::EX_42_EXPECTED_HEADER,
				'expectedSignature' => RFC7520Examples::EX_42_EXPECTED_SIGNATURE,

			],
		];
	}

	public static function RSAPSSalgoProvider():array{
		return [
			RSAPSS::ALGO_PS256 => [RSAPSS::ALGO_PS256, 2048],
			RSAPSS::ALGO_PS384 => [RSAPSS::ALGO_PS384, 3072],
			RSAPSS::ALGO_PS512 => [RSAPSS::ALGO_PS512, 4096],
		];
	}

	#[Test]
	#[DataProvider('RSAPSSalgoProvider')]
	public function RSAPSSsign(string $algo, int $keylength):void{
		$privateKey = (new RSAKey)->create(kid: $this::KID, size: $keylength);
		$jwkPrivate = Util::parseJWK($privateKey);
		$signAlgo   = new RSAPSS($jwkPrivate, $algo);

		$this->assertSign($signAlgo);
	}

}
