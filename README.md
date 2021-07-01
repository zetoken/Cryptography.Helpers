Cryptography Helpers by ZTn
===========================

Some extension methods to help with cryptography.

# ZTn.Cryptography.Helpers

A very simple library providing some extension methods for cryptographic purposes.
Most of these methods try to be *fluent* by returning the output.

## AES

### Using `Stream` with an implicit output stream
A MemoryStream is created internally, don't forget to dispose later.

The IV is automatically written to / read from the 16 first bytes of the output:

```cs
var key = new byte[] {/* key bytes */};

using var cipheredStream = await inputStream.AesEncryptAsync(key);

using var decipheredStream = await cipheredStream.AesDecryptAsync(key);
```

### Using a `Stream` with an explicit output stream
The IV is automatically written to / read from the 16 first bytes of the output:
```cs
var key = new byte[] {/* key bytes */};

using var cipheredStream = new MemoryStream();
await inputStream.AesEncryptAsync(cipheredStream, key);

using var decipheredStream = new MemoryStream();
await cipheredStream.AesDecryptAsync(decipheredStream, key);
```

The IV can also be explicitly defined:
```cs
var key = new byte[] {/* key bytes */};
var iv = new byte[] {/* IV bytes */};

using var cipheredStream = new MemoryStream();
await inputStream.AesEncryptAsync(cipheredStream, key, iv);

using var decipheredStream = new MemoryStream();
await cipheredStream.AesDecryptAsync(decipheredStream, key, iv);
```

### Using `byte[]`
```cs
var key = new byte[] {/* key bytes */};

var cipheredBytes = await inputBytes.AesEncryptAsync(key);

var decipheredBytes = await cipheredBytes.AesDecryptAsync(key);
```
