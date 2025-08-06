<?php
/**
 * Class Util
 *
 * @created      06.08.2024
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2024 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\JOSE;

use chillerlan\JOSE\Key\ECKey;
use chillerlan\JOSE\Key\JWK;
use chillerlan\JOSE\Key\OCTKey;
use chillerlan\JOSE\Key\OKPKey;
use chillerlan\JOSE\Key\RSAKey;
use InvalidArgumentException;
use OpenSSLAsymmetricKey;
use RuntimeException;
use function array_map;
use function chunk_split;
use function is_array;
use function json_decode;
use function json_encode;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use function sodium_base642bin;
use function sodium_bin2base64;
use function sprintf;
use function strtoupper;
use function trim;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use const JSON_UNESCAPED_UNICODE;
use const SODIUM_BASE64_VARIANT_ORIGINAL;
use const SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING;

final class Util{

	/**
	 * @return \chillerlan\JOSE\Key\JWK|\chillerlan\JOSE\Key\JWK[]
	 * @throws \RuntimeException
	 */
	public static function parseJWK(string $jwk):array|JWK{
		$data = self::jsonDecode($jwk);

		if(isset($data['keys'])){

			if(!is_array($data['keys'])){
				throw new RuntimeException('"keys" is not a valid JWK array');
			}

			return array_map(self::parseKey(...), $data['keys']);
		}

		return self::parseKey($data);
	}

	/**
	 * @param array<string, string> $keyData
	 * @throws \RuntimeException
	 */
	private static function parseKey(array $keyData):JWK{

		if(!isset($keyData['kty'])){
			throw new RuntimeException('JWK must contain a "kty" parameter');
		}

		return match($keyData['kty']){
			ECKey::KTY  => ECKey::parse($keyData),
			RSAKey::KTY => RSAKey::parse($keyData),
			OCTKey::KTY => OCTKey::parse($keyData),
			OKPKey::KTY => OKPKey::parse($keyData),
			default     => throw new RuntimeException('invalid key type'),
		};
	}

	/**
	 * @throws \SodiumException
	 */
	public static function base64encode(string $bin):string{
		return sodium_bin2base64($bin, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
	}

	/**
	 * @throws \SodiumException
	 */
	public static function base64decode(string $base64):string{
		return sodium_base642bin($base64, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING, '=');
	}

	/**
	 * @throws \JsonException
	 */
	public static function jsonEncode(mixed $data):string{
		return json_encode(value: $data, flags: (JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR));
	}

	/**
	 * @throws \JsonException
	 */
	public static function jsonDecode(string $json):mixed{
		return json_decode(json: $json, associative: true, flags: JSON_THROW_ON_ERROR);
	}

	public static function formatPEM(string $key, string $type = 'PUBLIC'):string{
		$key = chunk_split(sodium_bin2base64($key, SODIUM_BASE64_VARIANT_ORIGINAL), 64, "\n");
		// @todo
		return sprintf(
			'-----BEGIN %1$s KEY-----%3$s%2$s-----END %1$s KEY-----%3$s',
			strtoupper(trim($type)),
			$key,
			"\n",
		);
	}

	public static function parseKeyParams(array $keyData, array $keyParams, bool $base64decode = true):array{
		$key = [];

		foreach($keyParams as $param){
			if(isset($keyData[$param])){

				if($base64decode){
					$keyData[$param] = self::base64decode($keyData[$param]);
				}

				$key[$param] = $keyData[$param];
			}
		}

		return $key;
	}

	public static function loadPEM(string $pem):OpenSSLAsymmetricKey{
		// try private key first
		$key = openssl_pkey_get_private($pem);

		// ok, try public
		if($key === false){
			$key = openssl_pkey_get_public($pem);
		}

		// still nothing? bye!
		if($key === false){
			throw new InvalidArgumentException('invalid PEM');
		}

		return $key;
	}

}
