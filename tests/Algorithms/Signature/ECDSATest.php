<?php
/**
 * Class ECDSATest
 *
 * @created      09.08.2025
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2025 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\JOSETest\Algorithms\Signature;

use chillerlan\JOSE\Algorithms\Signature\ECDSA;
use chillerlan\JOSE\Key\ECKey;
use chillerlan\JOSE\Util;
use chillerlan\JOSETest\RFC7515Examples;
use chillerlan\JOSETest\RFC7520Examples;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

final class ECDSATest extends SignatureAlgoTestAbstract{

	protected const FQN = ECDSA::class;

	public static function algoProvider():array{
		return [
			// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.3
			'RFC7515-A3 (ES256)'  => [
				'alg'               => ECDSA::ALGO_ES256,
				'privateKey'        => RFC7515Examples::A3_JWK_PRIVATE,
				'publicKey'         => RFC7515Examples::A3_JWK_PUBLIC,
				'payloadString'     => Util::base64decode(RFC7515Examples::SIGN_PAYLOAD),
				'expectedHeader'    => RFC7515Examples::A3_EXPECTED_HEADER,
				'expectedSignature' => RFC7515Examples::A3_EXPECTED_SIGNATURE,
			],
			// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.4
			'RFC7515-A4 (ES512)'  => [
				'alg'               => ECDSA::ALGO_ES512,
				'privateKey'        => RFC7515Examples::A4_JWK_PRIVATE,
				'publicKey'         => RFC7515Examples::A4_JWK_PUBLIC,
				'payloadString'     => 'Payload',
				'expectedHeader'    => RFC7515Examples::A4_EXPECTED_HEADER,
				'expectedSignature' => RFC7515Examples::A4_EXPECTED_SIGNATURE,
			],
			// https://datatracker.ietf.org/doc/html/rfc7520#section-4.3
			'RFC7520-4.3 (ES512)' => [
				'alg'               => ECDSA::ALGO_ES512,
				'privateKey'        => RFC7520Examples::JWK_EC_PRIVATE,
				'publicKey'         => RFC7520Examples::JWK_EC_PUBLIC,
				'payloadString'     => RFC7520Examples::SIGN_PAYLOAD,
				'expectedHeader'    => RFC7520Examples::EX_43_EXPECTED_HEADER,
				'expectedSignature' => RFC7520Examples::EX_43_EXPECTED_SIGNATURE,
			],
		];
	}

	public static function ECDSAalgoProvider():array{
		return [
			ECDSA::ALGO_ES256  => [ECDSA::ALGO_ES256 , ECKey::CRV_P256 ],
			ECDSA::ALGO_ES256K => [ECDSA::ALGO_ES256K, ECKey::CRV_P256K],
			ECDSA::ALGO_ES384  => [ECDSA::ALGO_ES384 , ECKey::CRV_P384 ],
			ECDSA::ALGO_ES512  => [ECDSA::ALGO_ES512 , ECKey::CRV_P521 ],
		];
	}

	#[Test]
	#[DataProvider('ECDSAalgoProvider')]
	public function ECDSAsign(string $algo, string $crv):void{
		$privateKey = (new ECKey)->create(kid: $this::KID, crv: $crv);
		$jwkPrivate = Util::parseJWK($privateKey);
		$signAlgo   = new ECDSA($jwkPrivate, $algo);

		$this->assertSign($signAlgo);
	}

}
