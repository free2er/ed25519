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
    protected ?string $privateKey = null;

    /**
     * Открытый ключ
     *
     * @var string|null
     */
    protected ?string $publicKey = null;

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
     * Проверяет формирование закрытого ключа
     *
     * @throws Throwable
     */
    public function testGeneratePrivateKey(): void
    {
        $privateKey = Key::generate();
        $this->assertNotEmpty($privateKey->getPrivateKey());
        $this->assertNotEmpty($privateKey->getPublicKey());

        $publicKey = $privateKey->toPublic();
        $this->assertNull($publicKey->getPrivateKey());
        $this->assertNotEmpty($publicKey->getPublicKey());
        $this->assertEquals($privateKey->getPublicKey(), $publicKey->getPublicKey());

        $fromPrivate = $this->extractPublicKeyFromPrivateKey($privateKey);
        $this->assertNotEmpty($fromPrivate);

        $fromPublic = $this->extractPublicKeyFromPublicKey($publicKey);
        $this->assertEquals($fromPublic, $publicKey->toPem());
        $this->assertEquals($fromPrivate, $fromPublic);
    }

    /**
     * Проверяет создание ключа из файла
     */
    public function testLoadFromFile(): void
    {
        $key = Key::createFromKeyFile(__DIR__ . '/keys/private.key');
        $this->assertNotEmpty($key);
    }

    /**
     * Проверяет создание закрытого ключа
     *
     * @throws Throwable
     */
    public function testLoadPrivateKey(): void
    {
        $key = Key::createFromKey($this->privateKey);
        $this->assertNotEmpty($key->getPrivateKey());
        $this->assertNotEmpty($key->getPublicKey());
        $this->assertEquals($this->privateKey, $key->toPem());
        $this->assertEquals($this->publicKey, $key->toPublic()->toPem());
    }

    /**
     * Проверяет создание открытого ключа
     *
     * @throws Throwable
     */
    public function testLoadPublicKey(): void
    {
        $key = Key::createFromKey($this->publicKey);
        $this->assertNull($key->getPrivateKey());
        $this->assertNotEmpty($key->getPublicKey());
        $this->assertEquals($this->publicKey, $key->toPem());
        $this->assertEquals($this->publicKey, $key->toPublic()->toPem());
    }

    /**
     * Извлекает открытый ключ из закрытого ключа
     *
     * @param Key $key
     *
     * @return string
     *
     * @throws Throwable
     */
    private function extractPublicKeyFromPrivateKey(Key $key): string
    {
        $openssl = openssl_pkey_get_private($key->toPem());
        $this->assertNotEmpty($openssl);

        $details = openssl_pkey_get_details($openssl);
        openssl_pkey_free($openssl);

        return $details['key'];
    }

    /**
     * Извлекает открытый ключ из открытого ключа
     *
     * @param Key $key
     *
     * @return string
     *
     * @throws Throwable
     */
    private function extractPublicKeyFromPublicKey(Key $key): string
    {
        $openssl = openssl_pkey_get_public($key->toPem());
        $this->assertNotEmpty($openssl);

        $details = openssl_pkey_get_details($openssl);
        openssl_pkey_free($openssl);

        return $details['key'];
    }
}
