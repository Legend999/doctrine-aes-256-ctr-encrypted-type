# AES-256 CTR Doctrine Type

A custom Doctrine Type for AES-256 encryption in CTR mode.

## Installation

```bash
composer require d3d9ex/doctrine-aes-256-ctr-encrypted-type
```

## Configuration

```php
use D3d9ex\Aes256CtrEncryptedType\Aes256CtrEncrypted;
use Doctrine\DBAL\Types\Type;

/* ... */

Type::addType(Aes256CtrEncrypted::NAME, Aes256CtrEncrypted::class);
Aes256CtrEncrypted::setSecretKey(getenv('AES_KEY'));
```

## Usage

```php
use D3d9ex\Aes256CtrEncryptedType\Aes256CtrEncrypted;
use Doctrine\ORM\Mapping as ORM;

/* ... */

#[ORM\Entity]
#[ORM\Table(name: 'entities')]
class Entity
{
	#[ORM\Column(name: 'secret_value', type: Aes256CtrEncrypted::NAME)]
	private string $secretValue;
	
	/* ... */
}
```
