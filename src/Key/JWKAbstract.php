<?php
/**
 * Class JWKAbstract
 *
 * @created      06.08.2025
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2025 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\JOSE\Key;

use RuntimeException;

abstract class JWKAbstract implements JWK{

	public function __construct(
		protected string|null $privateKey = null,
		protected string|null $publicKey = null,
		protected string|null $algo = null,
		protected string|null $id = null,
	){
		// noop
	}

	public function getPrivateKey():string|null{
		return $this->privateKey;
	}

	public function getPublicKey():string|null{
		return $this->publicKey;
	}

	public function getAlgo():string|null{
		return $this->algo;
	}

	public function getID():string|null{
		return $this->id;
	}

	/**
	 * @return array{0: string|null, 1: string}
	 */
	abstract protected static function parseJWK(array $jsonKeyData):array;

	public static function parse(array $jsonKeyData):static{

		if(!isset($jsonKeyData['kty'])){
			throw new RuntimeException('JWK must contain a "kty" parameter');
		}

		if($jsonKeyData['kty'] !== static::KTY){
			throw new RuntimeException('invalid "kty" parameter');
		}
		/** @phan-suppress-next-line PhanAbstractStaticMethodCallInStatic */
		[$private, $public] = static::parseJWK($jsonKeyData);

		$kid = null;

		// the key id might not always be a string
		if(isset($jsonKeyData['kid'])){
			$kid = (string)$jsonKeyData['kid'];
		}
		/** @phan-suppress-next-line PhanTypeInstantiateAbstractStatic */
		return new static($private, $public, ($jsonKeyData['alg'] ?? null), $kid);
	}

}
