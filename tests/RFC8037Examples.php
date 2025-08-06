<?php
/**
 * Class RFC8037Examples
 *
 * @created      13.08.2024
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2024 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\JOSETest;

/**
 * @link https://datatracker.ietf.org/doc/html/rfc8037
 */
final class RFC8037Examples{

	// from https://datatracker.ietf.org/doc/html/rfc8037#appendix-A.1
	public const JWT_Ed25519_PRIVATE = '{
		"kty": "OKP",
		"crv": "Ed25519",
		"d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
		"x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	}';

	// https://datatracker.ietf.org/doc/html/rfc8037#appendix-A.2
	public const JWT_Ed25519_PUBLIC = '{
		"kty": "OKP",
		"crv": "Ed25519",
		"x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	}';

	// https://datatracker.ietf.org/doc/html/rfc8037#appendix-A.4
	public const SIGN_PAYLOAD = 'Example of Ed25519 signing';

	public const A4_EXPECTED_HEADER    = 'eyJhbGciOiJFZERTQSJ9';
	public const A4_EXPECTED_SIGNATURE = 'hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg';

}
