<?php
/**
 * Class EdDSATest
 *
 * @created      09.08.2025
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2025 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\JOSETest\Algorithms\Signature;

use chillerlan\JOSE\Algorithms\Signature\EdDSA;
use chillerlan\JOSETest\RFC8037Examples;

final class EdDSATest extends SignatureAlgoTestAbstract{

	protected const FQN = EdDSA::class;

	public static function algoProvider():array{
		return [
			// https://datatracker.ietf.org/doc/html/rfc8037#section-3.1
			'RFC8037-3.1 (EdDSA)' => [
				'alg'               => EdDSA::ALGO_EDDSA,
				'privateKey'        => RFC8037Examples::JWT_Ed25519_PRIVATE,
				'publicKey'         => RFC8037Examples::JWT_Ed25519_PUBLIC,
				'payloadString'     => RFC8037Examples::SIGN_PAYLOAD,
				'expectedHeader'    => RFC8037Examples::A4_EXPECTED_HEADER,
				'expectedSignature' => RFC8037Examples::A4_EXPECTED_SIGNATURE,
			],
		];
	}

}
