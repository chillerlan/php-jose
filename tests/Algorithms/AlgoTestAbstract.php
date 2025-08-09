<?php
/**
 * Class AlgoTEstAbstract
 *
 * @created      09.08.2025
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2025 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\JOSETest\Algorithms;

use PHPUnit\Framework\TestCase;
use const PHP_OS_FAMILY;
use const PHP_VERSION_ID;

/**
 * @link https://datatracker.ietf.org/doc/html/rfc7520
 * @link https://datatracker.ietf.org/doc/html/rfc8037
 */
abstract class AlgoTestAbstract extends TestCase{

	protected const FQN = '';
	protected const KID = 'kid-test-69420';

	protected function setUp():void{

		if(PHP_OS_FAMILY === 'Windows' && PHP_VERSION_ID < 80200){
			$this::markTestSkipped('PHP 8.1 under Windows might get hit with a bunch of OpenSSL errors');
		}

	}

	abstract public static function algoProvider():array;

}
