<?php

declare(strict_types=1);

namespace Free2er\Ed25519;

use PHPUnit\Framework\TestCase;
use Throwable;

/**
 * Тест ключа
 */
class KeyTest extends TestCase
{
    /**
     * Закрытый ключ
     *
     * @var string|null
     */
    protected $privateKey;

    /**
     * Открытый ключ
     *
     * @var string|null
     */
    protected $publicKey;

    /**
     * Инициализирует окружение перез запуском теста
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->privateKey = file_get_contents(__DIR__ . '/keys/private.key');
        $this->publicKey  = file_get_contents(__DIR__ . '/keys/public.key');
    }

    /**
     * Очищает окружение после завершения теста
     */
    protected function tearDown(): void
    {
        parent::tearDown();

        $this->privateKey = null;
        $this->publicKey  = null;
    }

    /**
     * Проверяет состав ключа
     *
     * @throws Throwable
     */
    public function testKey(): void
    {
        $privateKey = Key::generate();
        $this->assertNotEmpty($privateKey->getPrivateKey());
        $this->assertNotEmpty($privateKey->getPublicKey());

        $publicKey = $privateKey->toPublic();
        $this->assertNull($publicKey->getPrivateKey());
        $this->assertNotEmpty($publicKey->getPublicKey());
        $this->assertEquals($privateKey->getPublicKey(), $publicKey->getPublicKey());

        $fromPrivate = $this->extractOpenSslPublicKeyFromPrivateKey($privateKey);
        $this->assertNotEmpty($fromPrivate);

        $fromPublic = $this->extractOpenSslPublicKeyFromPublicKey($publicKey);
        $this->assertEquals($fromPublic, $publicKey->toPem());
        $this->assertEquals($fromPrivate, $fromPublic);
    }

    /**
     * Проверяет разбор закрытого ключа
     *
     * @throws Throwable
     */
    public function testPrivateKeyPem(): void
    {
        $key = Key::load($this->privateKey);

        $this->assertNotEmpty($key->getPrivateKey());
        $this->assertNotEmpty($key->getPublicKey());
        $this->assertEquals($this->privateKey, $key->toPem());
        $this->assertEquals($this->publicKey, $key->toPublic()->toPem());
    }

    /**
     * Проверяет разбор открытого ключа
     *
     * @throws Throwable
     */
    public function testPublicKeyPem(): void
    {
        $key = Key::load($this->publicKey);

        $this->assertNull($key->getPrivateKey());
        $this->assertNotEmpty($key->getPublicKey());
        $this->assertEquals($this->publicKey, $key->toPem());
        $this->assertEquals($this->publicKey, $key->toPublic()->toPem());
    }

    /**
     * Извлекает открытый ключ OpenSSL из закрытого ключа
     *
     * @param Key $key
     *
     * @return string
     *
     * @throws Throwable
     */
    private function extractOpenSslPublicKeyFromPrivateKey(Key $key): string
    {
        $openssl = openssl_pkey_get_private($key->toPem());
        $this->assertNotEmpty($openssl);

        $details = openssl_pkey_get_details($openssl);
        openssl_pkey_free($openssl);

        return $details['key'];
    }

    /**
     * Извлекает открытый ключ OpenSSL из открытого ключа
     *
     * @param Key $key
     *
     * @return string
     *
     * @throws Throwable
     */
    private function extractOpenSslPublicKeyFromPublicKey(Key $key): string
    {
        $openssl = openssl_pkey_get_public($key->toPem());
        $this->assertNotEmpty($openssl);

        $details = openssl_pkey_get_details($openssl);
        openssl_pkey_free($openssl);

        return $details['key'];
    }
}
