<?php

declare(strict_types=1);

namespace D3d9ex\Aes256CtrEncryptedType;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\Type;
use InvalidArgumentException;
use D3d9ex\Aes256CtrEncryptedType\Exceptions\MissingSecretKeyException;
use D3d9ex\Aes256CtrEncryptedType\Exceptions\OpensslDecryptionException;
use D3d9ex\Aes256CtrEncryptedType\Exceptions\OpensslEncryptionException;
use D3d9ex\Aes256CtrEncryptedType\Exceptions\OpensslIvLengthException;
use SensitiveParameter;

final class Aes256CtrEncrypted extends Type
{
	public const NAME = 'aes_256_ctr_encrypted';
	private const CIPHER = 'aes-256-ctr';
	private const DEFAULT_FIELD_LENGTH = 255;

	private static ?string $secretKey = null;

	public function getSQLDeclaration(array $column, AbstractPlatform $platform): string
	{
		return "VARBINARY(" . ($column['length'] ?? self::DEFAULT_FIELD_LENGTH) . ")";
	}

	public function convertToPHPValue(mixed $value, AbstractPlatform $platform): ?string
	{
		if (self::$secretKey === null) {
			throw new MissingSecretKeyException();
		}

		if ($value === null) {
			return null;
		}

		$iv_length = openssl_cipher_iv_length(self::CIPHER);
		if ($iv_length === false) {
			throw new OpensslIvLengthException();
		}

		$iv = substr($value, 0, $iv_length);
		$encryptedData = substr($value, $iv_length);
		$decryptedData = openssl_decrypt($encryptedData, self::CIPHER, self::$secretKey, OPENSSL_RAW_DATA, $iv);
		if ($decryptedData === false) {
			throw new OpensslDecryptionException();
		}

		return $decryptedData;
	}

	public function convertToDatabaseValue(mixed $value, AbstractPlatform $platform): ?string
	{
		if (self::$secretKey === null) {
			throw new MissingSecretKeyException();
		}

		if ($value === null) {
			return null;
		}

		$iv_length = openssl_cipher_iv_length(self::CIPHER);
		if ($iv_length === false || $iv_length < 1) {
			throw new OpensslIvLengthException();
		}

		$iv = random_bytes($iv_length);
		$encryptedData = openssl_encrypt($value, self::CIPHER, self::$secretKey, OPENSSL_RAW_DATA, $iv);
		if ($encryptedData === false) {
			throw new OpensslEncryptionException();
		}

		return $iv . $encryptedData;
	}

	public function getName(): string
	{
		return self::NAME;
	}

	public static function setSecretKey(#[SensitiveParameter] string $secretKey): void
	{
		$cipher_key_length = openssl_cipher_key_length(self::CIPHER);
		if (strlen($secretKey) !== $cipher_key_length) {
			throw new InvalidArgumentException("Secret key must be $cipher_key_length characters long!");
		}

		self::$secretKey = $secretKey;
	}
}
