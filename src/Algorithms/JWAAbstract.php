<?php
/**
 * Class JWAAbstract
 *
 * @created      08.08.2024
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2024 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\JOSE\Algorithms;

use chillerlan\JOSE\Key\JWK;
use RuntimeException;
use function array_key_exists;

/**
 * @link https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_algorithm_identifier
 */
abstract class JWAAbstract implements JWA{

	protected JWK    $jwk;
	protected string $algo;

	public function __construct(JWK $jwk, string $algo){

		if(!$this->isSupported($algo)){
			throw new RuntimeException('invalid algo');
		}

		$this->jwk  = $jwk;
		$this->algo = $algo;

		$jwkAlgo = $this->jwk->getAlgo();

		if($jwkAlgo !== null && $jwkAlgo !== $this->algo){
			throw new RuntimeException('key algo does not match the given algo');
		}

	}

	public function isSupported(string $algo):bool{
		return array_key_exists($algo, $this::SUPPORTED_ALGOS);
	}

	public function getJwk():JWK{
		return $this->jwk;
	}

	public function getName():string{
		return $this->algo;
	}

}
