<?php
/**
 * example-ec.php
 *
 * @created      19.08.2024
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2024 smiley
 * @license      MIT
 */
declare(strict_types=1);

use chillerlan\JOSE\Algorithms\Signature\ECDSA;
use chillerlan\JOSE\JWS;
use chillerlan\JOSE\Key\ECKey;
use chillerlan\JOSE\Util;

require_once __DIR__.'/../vendor/autoload.php';

$algo = 'ES256';

// key examples from: https://datatracker.ietf.org/doc/html/rfc7515#appendix-A
$privateJWK = '{
	"kty":"EC",
	"crv":"P-256",
	"x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
	"y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
	"d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
}';

// JWK to PEM conversion
#$privatePEM = (new ECKey)->privateKeyToPEM(Util::jsonDecode($privateJWK));
$privatePEM = '-----BEGIN EC PRIVATE KEY-----
MHcCAQEEII6bEJ5xkJi/mASH3x9dd+nLKWBuvtImO19XwhPfhPSyoAoGCCqGSM49
AwEHoUQDQgAEf83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEXH8UTNG72b
focs3+257rn0s2ldbqkLJK2KRiMohYjlrQ==
-----END EC PRIVATE KEY-----';

#$publicPEM = (new ECKey)->publicKeyToPEM(Util::jsonDecode($privateJWK));
$publicPEM = '-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEf83OJ3D2xF1Bg8vub9tLe1gHMzV7
6e8Tus9uPHvRVEXH8UTNG72bfocs3+257rn0s2ldbqkLJK2KRiMohYjlrQ==
-----END PUBLIC KEY-----';

// invoke a key from JWK...
$jwk = ECKey::parse(Util::jsonDecode($privateJWK));
// ...or PEM
$jwk = new ECKey(privateKey: $privatePEM, publicKey: $publicPEM);
// invoke the signature algorithm
$jwa = new ECDSA(jwk: $jwk, algo: $algo);
// invoke the signature
$jws = new JWS($jwa);
// encode and sign (requires private key
$jwt = $jws->encode(['foo' => 'bar']);
var_dump($jwt);
// decode and verify (requires public key)
var_dump($jws->decode($jwt));

#var_dump((new ECKey)->publicKeyToPEM(Util::jsonDecode($privateJWK)));
#var_dump((new ECKey)->pemToPrivateJWK($privatePEM));
