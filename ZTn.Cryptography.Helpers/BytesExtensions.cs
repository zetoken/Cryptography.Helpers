using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace ZTn.Cryptography.Helpers
{
    /// <summary>
    /// Cryptographic extension methods applying on byte arrays.
    /// </summary>
    public static class BytesExtensions
    {
        /// <summary>
        /// Decrypts the content of <paramref name="cipheredInput"/> to a new byte[] using the <paramref name="key" /> and <see cref="Aes" /> algorithm.
        /// </summary>
        /// <param name="cipheredInput">The input whose content is ciphered.</param>
        /// <param name="key">The secret AES key.</param>
        /// <returns>The new byte[] instance.</returns>
        /// <remarks>The 16 first bytes of the <paramref name="cipheredInput"/> must be the IV.</remarks>
        public static Task<byte[]> AesDecryptAsync(this byte[] cipheredInput, byte[] key)
        {
            _ = cipheredInput ?? throw new ArgumentNullException(nameof(cipheredInput));
            _ = key ?? throw new ArgumentNullException(nameof(key));

            var outputStream = new MemoryStream();

            return new MemoryStream(cipheredInput)
                .AesDecryptAsync(outputStream, key)
                .ContinueWith(t => t.Result.ToArray());
        }

        /// <summary>
        /// Encrypts the content of <paramref name="input"/> to a new byte[] using the <paramref name="key"/> and <see cref="Aes"/> algorithm.
        /// </summary>
        /// <param name="input">The input stream whose content is to be ciphered.</param>
        /// <param name="key">The secret AES key.</param>
        /// <returns>The new byte[] instance whose content is ciphered.</returns>
        /// <remarks>The 16 first bytes written to the output stream are the IV.</remarks>
        public static Task<byte[]> AesEncryptAsync(this byte[] input, byte[] key)
        {
            _ = input ?? throw new ArgumentNullException(nameof(input));
            _ = key ?? throw new ArgumentNullException(nameof(key));

            var outputStream = new MemoryStream();

            return new MemoryStream(input)
                .AesEncryptAsync(outputStream, key)
                .ContinueWith(t => t.Result.ToArray());
        }

        /// <summary>
        /// Decrypts the content of <paramref name="cipheredInput"/> stream using the <paramref name="key1"/> and encrypts the data again to a new byte[] using <paramref name="key2"/> and <see cref="Aes"/> algorithm.
        /// </summary>
        /// <param name="cipheredInput">The input stream whose content is ciphered with <paramref name="key1"/>.</param>
        /// <param name="key1">The secret AES key used to decrypt the <paramref name="cipheredInput"/> stream content.</param>
        /// <param name="key2">The secret AES key used to encrypt the data to the returned byte[].</param>
        /// <returns>The new byte[] instance whose content is ciphered.</returns>
        /// <remarks>
        /// The 16 first bytes of the <paramref name="cipheredInput"/> must be the IV.
        /// The 16 first bytes written to returned byte[] are the IV.
        /// </remarks>
        public static Task<byte[]> AesTranscryptAsync(this byte[] cipheredInput, byte[] key1, byte[] key2)
        {
            _ = cipheredInput ?? throw new ArgumentNullException(nameof(cipheredInput));
            _ = key1 ?? throw new ArgumentNullException(nameof(key1));
            _ = key2 ?? throw new ArgumentNullException(nameof(key2));

            var outputStream = new MemoryStream();

            return new MemoryStream(cipheredInput)
                .AesTranscryptAsync(outputStream, key1, key2)
                .ContinueWith(t => t.Result.ToArray());
        }
    }
}