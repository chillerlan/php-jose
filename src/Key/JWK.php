<?php
/**
 * Interface JWK
 *
 * @created      06.08.2025
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2025 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\JOSE\Key;

/**
 * JSON Web Key (JWK)
 *
 * @link https://datatracker.ietf.org/doc/html/rfc7517
 * @link https://datatracker.ietf.org/doc/html/rfc8037
 */
interface JWK{

	public const KTY = '';

	public const PARAMS_PRIVATE = [];
	public const PARAMS_PUBLIC  = [];

	public static function parse(array $jsonKeyData):static;

	public function getPrivateKey():string;

	public function getPublicKey():string;

	public function getAlgo():string|null;

	public function getID():string|null;

	public function getUse():string|null;

	public function create(string|null $kid = null, string|null $use = null):array;

	public function toPrivateJWK(string|null $kid = null, string|null $use = null):array;

	public function toPublicJWK(string|null $kid = null, string|null $use = null):array;

}
