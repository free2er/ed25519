# ed25519
Ed25519 key tools

## Installation
This component can be installed with the [Composer](https://getcomposer.org/) dependency manager.

1. [Install Composer](https://getcomposer.org/doc/00-intro.md)

2. Install the component as a dependency of your project

        composer require free2er/ed25519

## Usage

Generate new key
```php
use Free2er\Ed25519\Key;

$privateKey = Key::generate();

echo $privateKey->toPem();
echo $privateKey->toPublic()->toPem();
```

Load key from OpenSSL file
```php
use Free2er\Ed25519\Key;

$privateKey = Key::loadFromFile('/path/to/private.key');
echo $privateKey->toPem();
echo $privateKey->toPublic()->toPem();

$publicKey = Key::loadFromFile('/path/to/public.key');
echo $publicKey->toPem();
```

## OpenSSL commands 

Generate private key
```shell script
openssl genpkey -algorithm Ed25519 -out private.key
```

Extract public key
```shell script
openssl pkey -in private.key -pubout -out public.key
```
