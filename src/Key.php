<?php

declare(strict_types=1);

namespace Free2er\Ed25519;

use FG\ASN1\Identifier;
use FG\ASN1\TemplateParser;
use FG\ASN1\Universal\BitString;
use FG\ASN1\Universal\Integer;
use FG\ASN1\Universal\ObjectIdentifier;
use FG\ASN1\Universal\OctetString;
use FG\ASN1\Universal\Sequence;
use Throwable;
use UnexpectedValueException;

/**
 * Ключ
 */
class Key
{
    /**
     * OID Ed25519
     */
    private const OID = '1.3.101.112';

    /**
     * Шаблон проверки PEM
     */
    private const PEM = "/^-----BEGIN (PUBLIC|PRIVATE) KEY-----\n(.+)\n-----END (PUBLIC|PRIVATE) KEY-----\n$/";

    /**
     * Закрытый ключ
     *
     * @var string|null
     */
    private $privateKey;

    /**
     * Открытый ключ
     *
     * @var string
     */
    private $publicKey;

    /**
     * Формирует закрытый ключ
     *
     * @return static
     */
    public static function generate(): self
    {
        $keyPair = sodium_crypto_sign_keypair();

        return static::privateKeyFromSodiumKeyPair($keyPair);
    }

    /**
     * Загружает ключ OpenSSL
     *
     * @param string $pemKey
     *
     * @return static|null
     */
    public static function load(string $pemKey): ?self
    {
        if (!preg_match(static::PEM, $pemKey, $match)) {
            return null;
        }

        if (!$binary = base64_decode($match[2])) {
            return null;
        }

        try {
            return $match[1] === 'PUBLIC' ? static::publicKey($binary) : static::privateKey($binary);
        } catch (Throwable $exception) {
            return null;
        }
    }

    /**
     * Создает открытый ключ
     *
     * @param string $binary
     *
     * @return static
     *
     * @throws Throwable
     */
    private static function publicKey(string $binary): self
    {
        $parser = new TemplateParser();
        $asn1   = $parser->parseBinary($binary, [
            Identifier::SEQUENCE => [
                Identifier::SEQUENCE => [Identifier::OBJECT_IDENTIFIER],
                Identifier::BITSTRING,
            ],
        ]);

        static::assertOid($asn1[0][0]->getContent());

        $publicKey = $asn1[1]->getBinaryContent();
        $publicKey = ltrim($publicKey, "\0");

        return new static($publicKey);
    }

    /**
     * Создает закрытый ключ
     *
     * @param string $binary
     *
     * @return static
     *
     * @throws Throwable
     */
    private static function privateKey(string $binary): self
    {
        $parser = new TemplateParser();
        $asn1   = $parser->parseBinary($binary, [
            Identifier::SEQUENCE => [
                Identifier::INTEGER,
                Identifier::SEQUENCE => [Identifier::OBJECT_IDENTIFIER],
                Identifier::OCTETSTRING,
            ],
        ]);

        static::assertOid($asn1[1][0]->getContent());

        $keyPair = $asn1[2]->getBinaryContent();
        $keyPair = $parser->parseBinary($keyPair, [Identifier::OCTETSTRING])->getBinaryContent();
        $keyPair = sodium_crypto_sign_seed_keypair($keyPair);

        return static::privateKeyFromSodiumKeyPair($keyPair);
    }

    /**
     * Создает закрытый ключ из пары Sodium
     *
     * @param string $keyPair
     *
     * @return static
     */
    private static function privateKeyFromSodiumKeyPair(string $keyPair): self
    {
        $publicKey  = sodium_crypto_sign_publickey($keyPair);
        $secretKey  = sodium_crypto_sign_secretkey($keyPair);
        $privateKey = substr($secretKey, 0, intval(strlen($secretKey) / 2));

        return new static($publicKey, $privateKey);
    }

    /**
     * Проверяет OID ключа
     *
     * @param string $oid
     *
     * @throws UnexpectedValueException
     */
    private static function assertOid(string $oid): void
    {
        if ($oid === static::OID) {
            return;
        }

        throw new UnexpectedValueException(sprintf('OID must be %s, %s received', static::OID, $oid));
    }

    /**
     * Конструктор
     *
     * @param string      $publicKey
     * @param string|null $privateKey
     */
    public function __construct(string $publicKey, string $privateKey = null)
    {
        $this->privateKey = $privateKey;
        $this->publicKey  = $publicKey;
    }

    /**
     * Возвращает закрытый ключ
     *
     * @return string|null
     */
    public function getPrivateKey(): ?string
    {
        return $this->privateKey;
    }

    /**
     * Возвращает открытый ключ
     *
     * @return string
     */
    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    /**
     * Извлекает открытый ключ
     *
     * @return Key
     */
    public function toPublic(): Key
    {
        return $this->privateKey ? new static($this->publicKey) : $this;
    }

    /**
     * Формирует PEM ключа
     *
     * @return string
     *
     * @throws Throwable
     */
    public function toPem(): string
    {
        if ($this->privateKey) {
            $type = 'PRIVATE';
            $asn1 = new OctetString(bin2hex($this->privateKey));
            $asn1 = new Sequence(
                new Integer(0),
                new Sequence(new ObjectIdentifier(static::OID)),
                new OctetString(bin2hex($asn1->getBinary()))
            );
        } else {
            $type = 'PUBLIC';
            $asn1 = new Sequence(
                new Sequence(new ObjectIdentifier(static::OID)),
                new BitString(bin2hex($this->publicKey))
            );
        }

        return implode("\n", [
            sprintf('-----BEGIN %s KEY-----', $type),
            base64_encode($asn1->getBinary()),
            sprintf('-----END %s KEY-----', $type),
            '',
        ]);
    }
}
