<?php
/**
 * Class OpenSSLAbstract
 *
 * @created      10.08.2024
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2024 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\JOSE\Algorithms;

use chillerlan\JOSE\Key\JWK;
use OpenSSLAsymmetricKey;
use RuntimeException;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use function openssl_sign;
use function openssl_verify;

/**
 * PHP 8.1 under Windows might get hit with a bunch of OpenSSL errors:
 *
 * error:25070067:DSO support routines:DSO_load:could not load the shared library
 * error:0E07506E:configuration file routines:module_load_dso:error loading dso
 * error:0E076071:configuration file routines:module_run:unknown module name
 * error:0909006C:PEM routines:get_name:no start line
 *
 * derived from web-token/jwt-framework
 *
 * @link https://github.com/web-token/jwt-framework/blob/4af252f28996bfb8ce5eac78037a555dce222829/src/Library/Signature/Algorithm/Util/RSA.php
 */
abstract class OpenSSLAbstract extends JWAAbstract{

	protected const KEYTYPE = -1;

	private string|null $passphrase;

	public function __construct(JWK $jwk, string $algo, string|null $passphrase = null){
		parent::__construct($jwk, $algo);

		$this->passphrase = $passphrase;
	}

	abstract protected function checkKeyLength(int $bits):bool;

	protected function signMessage(string $message):string{

		if(openssl_sign($message, $signature, $this->jwk->getPrivateKey(), $this::SUPPORTED_ALGOS[$this->algo]) === false){
			throw new RuntimeException('openssl_sign error');
		}

		return $signature;
	}

	protected function verifySignature(string $message, string $signature):bool{
		$verified = openssl_verify($message, $signature, $this->getPublicKey(), $this::SUPPORTED_ALGOS[$this->algo]);

		return $verified === 1;
	}

	protected function getPrivateKey():OpenSSLAsymmetricKey{
		/** @phan-suppress-next-line PhanTypeMismatchArgumentNullableInternal */
		return $this->verifyKey(openssl_pkey_get_private($this->jwk->getPrivateKey(), $this->passphrase));
	}

	/**
	 * @return array<string, string|array<string, string>>
	 * @throws \RuntimeException
	 */
	protected function getPrivateKeyDetails():array{
		$details = openssl_pkey_get_details($this->getPrivateKey());

		if($details === false){
			throw new RuntimeException('could not get private key details');
		}

		return $details;
	}

	protected function getPublicKey():OpenSSLAsymmetricKey{
		return $this->verifyKey(openssl_pkey_get_public($this->jwk->getPublicKey()));
	}

	/**
	 * @return array<string, string|array<string, string>>
	 * @throws \RuntimeException
	 */
	protected function getPublicKeyDetails():array{
		$details = openssl_pkey_get_details($this->getPublicKey());

		if($details === false){
			throw new RuntimeException('could not get public key details');
		}

		return $details;
	}

	/**
	 * @throws \RuntimeException
	 */
	private function verifyKey(OpenSSLAsymmetricKey|false $key):OpenSSLAsymmetricKey{

		if($key === false){
			throw new RuntimeException('invalid key');
		}

		$details = openssl_pkey_get_details($key);

		if($details === false){
			throw new RuntimeException('could not get key details');
		}

		if($details['type'] !== $this::KEYTYPE){
			throw new RuntimeException('invalid key type');
		}

		if(!$this->checkKeyLength($details['bits'])){
			throw new RuntimeException('invalid key length');
		}

		return $key;
	}

}
