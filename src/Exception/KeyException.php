<?php

declare(strict_types=1);

namespace Free2er\Ed25519\Exception;

use RuntimeException;
use Throwable;

/**
 * Ошибка создания ключа
 */
class KeyException extends RuntimeException
{
    /**
     * Конструктор
     *
     * @param string         $message
     * @param Throwable|null $previous
     */
    public function __construct(string $message, Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
    }
}
