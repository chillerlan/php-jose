<?php
/**
 * Class RSAPSS
 *
 * @created      13.08.2024
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2024 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\JOSE\Algorithms\Signature;

use chillerlan\JOSE\Algorithms\OpenSSLAbstract;
use chillerlan\JOSE\Key\RSAKey;
use chillerlan\JOSE\Util;
use GMP;
use InvalidArgumentException;
use RuntimeException;
use function array_map;
use function ceil;
use function chr;
use function gmp_add;
use function gmp_export;
use function gmp_import;
use function gmp_mod;
use function gmp_mul;
use function gmp_powm;
use function gmp_sub;
use function hash;
use function hash_equals;
use function ord;
use function pack;
use function random_bytes;
use function str_pad;
use function str_repeat;
use function strlen;
use function substr;
use const OPENSSL_KEYTYPE_RSA;
use const STR_PAD_LEFT;

/**
 * RSA-PSS Signature Algorithm
 *
 * derived from web-token/jwt-framework
 *
 * @link https://github.com/web-token/jwt-framework/blob/4af252f28996bfb8ce5eac78037a555dce222829/src/Library/Signature/Algorithm/Util/RSA.php
 */
final class RSAPSS extends OpenSSLAbstract implements SignatureAlgorithm{

	public const ALGO_PS256 = 'PS256';
	public const ALGO_PS384 = 'PS384';
	public const ALGO_PS512 = 'PS512';

	public const SUPPORTED_ALGOS = [
		self::ALGO_PS256 => 'SHA256',
		self::ALGO_PS384 => 'SHA384',
		self::ALGO_PS512 => 'SHA512',
	];

	protected const KEYTYPE = OPENSSL_KEYTYPE_RSA;

	private const HASH_LENGTH = [
		'SHA256' => 32,
		'SHA384' => 48,
		'SHA512' => 64,
	];

	public function sign(string $message):string{
		$key       = Util::filterKeyParams($this->getPrivateKeyDetails()['rsa'], RSAKey::PARAMS_OPENSSL, false);
		$modlen    = strlen($key['n']);
		$em        = $this->encodeEMSAPSS($message, (8 * $modlen - 1), $this::SUPPORTED_ALGOS[$this->algo]);
		$signature = $this->exponentiate($key, $em, $modlen);

		if($signature === ''){
			throw new RuntimeException('Invalid signature.'); // @codeCoverageIgnore
		}

		return $signature;
	}

	public function verify(string $message, string $signature):bool{
		$key    = Util::filterKeyParams($this->getPublicKeyDetails()['rsa'], ['n', 'e'], false);
		$modlen = strlen($key['n']);

		if(strlen($signature) !== $modlen){
			throw new InvalidArgumentException('invalid signature or key'); // @codeCoverageIgnore
		}

		$em = $this->exponentiate($key, $signature, $modlen);

		return $this->verifyEMSAPSS($message, $em, (8 * $modlen - 1), $this::SUPPORTED_ALGOS[$this->algo]);
	}

	protected function checkKeyLength(int $bits):bool{
		return $bits >= 2048;
	}

	private function encodeEMSAPSS(string $message, int $modulusLength, string $hashName):string{
		$emLen = (($modulusLength + 1) >> 3);
		$sLen  = $this::HASH_LENGTH[$hashName];

		if($emLen <= (2 * $sLen + 2)){
			throw new RuntimeException;  // @codeCoverageIgnore
		}

		$mHash    = hash($hashName, $message, true);
		$salt     = random_bytes($sLen);
		$m2       = str_repeat("\x00", 8).$mHash.$salt;
		$h        = hash($hashName, $m2, true);
		$ps       = str_repeat("\x00", ($emLen - 2 * $sLen - 2));
		$db       = $ps."\x01".$salt;
		$dbMask   = $this->getMGF1($h, ($emLen - $sLen - 1), $hashName);
		$maskedDB = ($db ^ $dbMask);

		$maskedDB[0] = ($maskedDB[0] & ~chr(0xFF << ($modulusLength & 7)));

		return $maskedDB.$h."\xBC";
	}

	private function verifyEMSAPSS(string $m, string $em, int $emBits, string $hashName):bool{
		$hl    = $this::HASH_LENGTH[$hashName];
		$emLen = (($emBits + 1) >> 3);
		$sLen  = $hl;

		if($emLen < ($hl + $sLen + 2)){
			throw new InvalidArgumentException; // @codeCoverageIgnore
		}

		if($em[(strlen($em) - 1)] !== "\xBC"){
			throw new InvalidArgumentException; // @codeCoverageIgnore
		}

		$maskedDB = substr($em, 0, (-$hl - 1));
		$h        = substr($em, (-$hl - 1), $hl);
		$temp     = chr(0xFF << ($emBits & 7));

		if((~$maskedDB[0] & $temp) !== $temp){
			throw new InvalidArgumentException; // @codeCoverageIgnore
		}

		$dbMask = $this->getMGF1($h, ($emLen - $hl - 1), $hashName);
		$db     = ($maskedDB ^ $dbMask);
		$db[0]  = ($db[0] & ~chr(0xFF << ($emBits & 7)));
		$temp   = ($emLen - $hl - $sLen - 2);

		if(substr($db, 0, $temp) !== str_repeat("\x00", $temp)){
			throw new InvalidArgumentException; // @codeCoverageIgnore
		}

		if(ord($db[$temp]) !== 1){
			throw new InvalidArgumentException; // @codeCoverageIgnore
		}

		$mHash = hash($hashName, $m, true);
		$salt  = substr($db, ($temp + 1)); // should be $sLen long
		$m2    = str_repeat("\x00", 8).$mHash.$salt;
		$h2    = hash($hashName, $m2, true);

		return hash_equals($h, $h2);
	}

	private function toOctetString(GMP $x, int $xLen):string{
		$x = gmp_export($x);

		if(strlen($x) > $xLen){
			throw new RuntimeException; // @codeCoverageIgnore
		}

		return str_pad($x, $xLen, "\x00", STR_PAD_LEFT);
	}

	/**
	 * @param array<string, string> $key
	 */
	private function exponentiate(array $key, string $c, int $len):string{
		$key = array_map(gmp_import(...), $key);
		$c   = gmp_import($c);

		if(!isset($key['p'], $key['q'], $key['dmp1'], $key['dmq1'], $key['iqmp'])){
			return $this->toOctetString(gmp_powm($c, $key['e'], $key['n']), $len);
		}

		$m1 = gmp_powm($c, $key['dmp1'], $key['p']);
		$m2 = gmp_powm($c, $key['dmq1'], $key['q']);
		$g  = gmp_add(gmp_sub($m1, $m2), $key['p']);
		$h  = gmp_mod(gmp_mul($key['iqmp'], $g), $key['p']);
		$m  = gmp_add($m2, gmp_mul($h, $key['q']));

		return $this->toOctetString($m, $len);
	}

	private function getMGF1(string $mgfSeed, int $maskLen, string $hashName):string{
		$count = ceil($maskLen / $this::HASH_LENGTH[$hashName]);
		$t     = '';

		for($i = 0; $i < $count; ++$i){
			$c  = pack('N', $i);
			$t .= hash($hashName, $mgfSeed.$c, true);
		}

		return substr($t, 0, $maskLen);
	}

}
