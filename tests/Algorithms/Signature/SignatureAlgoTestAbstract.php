<?php
/**
 * Class SignatureAlgoTestAbstract
 *
 * @created      09.08.2025
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2025 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\JOSETest\Algorithms\Signature;

use chillerlan\JOSE\Algorithms\Signature\ECDSA;
use chillerlan\JOSE\Algorithms\Signature\RSAPSS;
use chillerlan\JOSE\Algorithms\Signature\SignatureAlgorithm;
use chillerlan\JOSE\JWS;
use chillerlan\JOSE\Util;
use chillerlan\JOSETest\Algorithms\AlgoTestAbstract;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function explode;
use function in_array;

abstract class SignatureAlgoTestAbstract extends AlgoTestAbstract{

	protected function assertSign(SignatureAlgorithm $signAlgo):void{
		$jws = new JWS($signAlgo);

		$expectedHeader     = ['typ' => 'JWT', 'alg' => $signAlgo->getName(), 'kid' => $this::KID];
		$expectedPayload    = ['foo' => 'bar'];
		$jwt                = $jws->encode($expectedPayload);
		[$header, $payload] = $jws->decode($jwt);

		$this::assertSame($expectedHeader,  Util::jsonDecode($header));
		$this::assertSame($expectedPayload, Util::jsonDecode($payload));
	}

	#[Test]
	#[DataProvider('algoProvider')]
	public function rfcSignExamples(
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
		/** @phan-suppress-next-line PhanEmptyFQSENInClasslike, PhanTypeExpectedObjectOrClassName */
		$signAlgo   = new (static::FQN)($jwkPrivate, $alg);
		// init signature
		$jws        = new JWS($signAlgo);
		// sign with private key
		$jwt        = $jws->encode($payloadString, ['alg' => $alg], false);

		[$header, $payload, $signature] = explode('.', $jwt);

		$this::assertSame($expectedHeader, $header);
		$this::assertSame(Util::base64encode($payloadString), $payload);

		// EC type algorithm hashes are random
		if(!in_array($this::FQN, [ECDSA::class, RSAPSS::class], true)){
			$this::assertSame($expectedSignature, $signature);
		}

		// verify with public key parsed from a JWK string
		$jwkPublic  = Util::parseJWK($publicKey);
		/** @phan-suppress-next-line PhanEmptyFQSENInClasslike, PhanTypeExpectedObjectOrClassName */
		$verifyAlgo = new (static::FQN)($jwkPublic, $alg);

		$this::assertTrue($verifyAlgo->verify($header.'.'.$payload, Util::base64decode($expectedSignature)));
		// this covers the EC random hashes too
		$this::assertTrue($verifyAlgo->verify($header.'.'.$payload, Util::base64decode($signature)));

		$this::assertSame([Util::base64decode($expectedHeader), $payloadString], $jws->decode($jwt));
	}

}
