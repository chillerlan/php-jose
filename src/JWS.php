<?php
/**
 * Class JWS
 *
 * @created      05.08.2024
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2024 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\JOSE;

use chillerlan\JOSE\Algorithms\Signature\SignatureAlgorithm;
use RuntimeException;
use function array_key_exists;
use function array_map;
use function explode;
use function is_array;
use function is_object;
use function is_string;
use function sprintf;

/**
 * JSON Web Signature (JWS)
 *
 * @link https://datatracker.ietf.org/doc/html/rfc7515
 */
final class JWS implements JWT{

	public function __construct(
		protected SignatureAlgorithm $algo,
	){
		// noop
	}

	public function encode(object|array|string $payload, array|null $headers = null, bool|null $jsonEncodeString = null):string{
		$headers ??= ['typ' => 'JWT'];
		// set the "alg" param from the given algorithm
		$headers['alg'] = $this->algo->getName();

		// only set the "kid" param when none was set before
		if(!isset($headers['kid'])){
			$kid = $this->algo->getJwk()->getID();

			if($kid !== null){
				$headers['kid'] = $kid;
			}
		}

		if((is_string($payload) && $jsonEncodeString === true) || is_array($payload) || is_object($payload)){
			$payload = Util::jsonEncode($payload);
		}

		$jwt = sprintf('%s.%s', Util::base64encode(Util::jsonEncode($headers)), Util::base64encode($payload));
		$sig = Util::base64encode($this->algo->sign($jwt));

		return sprintf('%s.%s', $jwt, $sig);
	}

	public function decode(string $jwt):array{
		[$b64header, $b64payload, $b64signature] = explode('.', $jwt);
		[$header, $payload, $signature]          = array_map(Util::base64decode(...), [$b64header, $b64payload, $b64signature]);

		if(!$this->algo->verify($b64header.'.'.$b64payload, $signature)){
			throw new RuntimeException('signature verification failed'); // @codeCoverageIgnore
		}

		$decodedHeader = Util::jsonDecode($header);

		// honestly we do not care if the "alg" parameter is present, but we'll check it in case it is
		if(array_key_exists('alg', $decodedHeader) && $decodedHeader['alg'] !== $this->algo->getName()){
			throw new RuntimeException(sprintf('invalid "alg" parameter: "%s"', $decodedHeader['alg'])); // @codeCoverageIgnore
		}

		return [$decodedHeader, $payload];
	}

}
