using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace ZTn.Cryptography.Helpers
{
    /// <summary>
    /// Cryptographic extension methods applying on <see cref="Stream"/>s.
    /// </summary>
    public static class StreamExtensions
    {
        #region >> AesDecrypt

        /// <summary>
        /// Decrypts the content of <paramref name="cipheredInput"/> stream to a new <see cref="MemoryStream"/> using the <paramref name="key" /> and <see cref="Aes" /> algorithm.
        /// </summary>
        /// <param name="cipheredInput">The input stream whose content is ciphered.</param>
        /// <param name="key">The secret AES key.</param>
        /// <param name="leaveOpen"><c>true</c> to not close the input stream once the encryption is done, otherwise <c>false</c>.</param>
        /// <returns>The new <see cref="MemoryStream"/> instance.</returns>
        /// <remarks>The 16 first bytes of the <paramref name="cipheredInput"/> stream must be the IV.</remarks>
        public static async Task<MemoryStream> AesDecryptAsync(this Stream cipheredInput, byte[] key, bool leaveOpen = false)
        {
            var outputStream = new MemoryStream();

            return await cipheredInput.AesDecryptAsync(outputStream, key, leaveOpen);
        }

        /// <summary>
        /// Decrypts the content of <paramref name="cipheredInput"/> stream to the <paramref name="output"/> stream using the <paramref name="key" /> and <see cref="Aes" /> algorithm.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="cipheredInput">The input stream whose content is ciphered.</param>
        /// <param name="output">The output stream.</param>
        /// <param name="key">The secret AES key.</param>
        /// <param name="leaveOpen"><c>true</c> to not close the input stream once the encryption is done, otherwise <c>false</c>.</param>
        /// <returns>The <paramref name="output"/> stream.</returns>
        /// <remarks>The 16 first bytes of the <paramref name="cipheredInput"/> stream must be the IV.</remarks>
        public static async Task<T> AesDecryptAsync<T>(this Stream cipheredInput, T output, byte[] key, bool leaveOpen = false)
            where T : Stream
        {
            var iv = new byte[16];
            await cipheredInput.ReadAsync(iv.AsMemory(0, 16));

            return await cipheredInput.AesDecryptAsync(output, key, iv, leaveOpen);
        }

        /// <summary>
        /// Decrypts the content of <paramref name="cipheredInput"/> stream to the <paramref name="output"/> stream using the <paramref name="key" /> and <paramref name="iv"/> and <see cref="Aes" /> algorithm.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="cipheredInput">The input stream whose content is ciphered.</param>
        /// <param name="output">The output stream.</param>
        /// <param name="key">The secret AES key.</param>
        /// <param name="iv">The AES initialization vector.</param>
        /// <param name="leaveOpen"><c>true</c> to not close the input stream once the encryption is done, otherwise <c>false</c>.</param>
        /// <returns>The <paramref name="output"/> stream.</returns>
        public static async Task<T> AesDecryptAsync<T>(this Stream cipheredInput, T output, byte[] key, byte[] iv, bool leaveOpen = false)
            where T : Stream
        {
            _ = key ?? throw new ArgumentNullException(nameof(key));
            _ = iv ?? throw new ArgumentNullException(nameof(iv));

            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;

            return await cipheredInput.AesDecryptAsync(output, aes, leaveOpen);
        }

        /// <summary>
        /// Decrypts the content of <paramref name="cipheredInput" /> stream to the <paramref name="output" /> stream using the <paramref name="aes" /> key and <see cref="Aes" /> algorithm.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="cipheredInput">The input stream whose content is ciphered.</param>
        /// <param name="output">The output stream.</param>
        /// <param name="aes">The <see cref="Aes"/> key.</param>
        /// <param name="leaveOpen"><c>true</c> to not close the input stream once the encryption is done, otherwise <c>false</c>.</param>
        /// <returns>The <paramref name="output"/> stream.</returns>
        public static async Task<T> AesDecryptAsync<T>(this Stream cipheredInput, T output, Aes aes, bool leaveOpen = false)
            where T : Stream
        {
            _ = cipheredInput ?? throw new ArgumentNullException(nameof(cipheredInput));
            _ = output ?? throw new ArgumentNullException(nameof(output));
            _ = aes ?? throw new ArgumentNullException(nameof(aes));

            using var decryptor = aes.CreateDecryptor();

            await using var cryptoStream = new CryptoStream(cipheredInput, decryptor, CryptoStreamMode.Read, leaveOpen);

            await cryptoStream.CopyToAsync(output);

            return output;
        }

        #endregion

        #region >> AesEncryptAsync

        /// <summary>
        /// Encrypts the content of <paramref name="input"/> stream to a new <see cref="MemoryStream"/> stream using the <paramref name="key"/> and <see cref="Aes"/> algorithm.
        /// </summary>
        /// <param name="input">The input stream whose content is to be ciphered.</param>
        /// <param name="key">The secret AES key.</param>
        /// <param name="leaveOpen"><c>true</c> to not close the input stream once the decryption is done, otherwise <c>false</c>.</param>
        /// <returns>The new <see cref="MemoryStream"/> instance whose content is ciphered.</returns>
        /// <remarks>The 16 first bytes written to the returned stream are the IV.</remarks>
        public static async Task<MemoryStream> AesEncryptAsync(this Stream input, byte[] key, bool leaveOpen = false)
        {
            var outputStream = new MemoryStream();

            return await input.AesEncryptAsync(outputStream, key, leaveOpen);
        }

        /// <summary>
        /// Encrypts the content of <paramref name="input"/> stream to the <paramref name="cipheredOutput"/> stream using the <paramref name="key"/> and <see cref="Aes"/> algorithm.
        /// </summary>
        /// <typeparam name="T">Type of the output stream.</typeparam>
        /// <param name="input">The input stream whose content is to be ciphered.</param>
        /// <param name="cipheredOutput">The output stream.</param>
        /// <param name="key">The secret AES key.</param>
        /// <param name="leaveOpen"><c>true</c> to not close the input stream once the decryption is done, otherwise <c>false</c>.</param>
        /// <returns>The <paramref name="cipheredOutput"/> stream.</returns>
        /// <remarks>The 16 first bytes written to <paramref name="cipheredOutput"/> stream are the IV.</remarks>
        public static async Task<T> AesEncryptAsync<T>(this Stream input, T cipheredOutput, byte[] key, bool leaveOpen = false)
            where T : Stream
        {
            _ = key ?? throw new ArgumentNullException(nameof(key));

            using var aes = Aes.Create();
            aes.Key = key;

            return await input.AesEncryptAsync(cipheredOutput, aes, leaveOpen);
        }

        /// <summary>
        /// Encrypts the content of <paramref name="input"/> stream to the <paramref name="cipheredOutput"/> stream using the <paramref name="key"/> and <paramref name="iv"/> and <see cref="Aes"/> algorithm.
        /// </summary>
        /// <typeparam name="T">Type of the output stream.</typeparam>
        /// <param name="input">The input stream whose content is to be ciphered.</param>
        /// <param name="cipheredOutput">The output stream.</param>
        /// <param name="key">The secret AES key.</param>
        /// <param name="iv">The AES initialization vector.</param>
        /// <param name="leaveOpen"><c>true</c> to not close the input stream once the decryption is done, otherwise <c>false</c>.</param>
        /// <returns>The <paramref name="cipheredOutput"/> stream.</returns>
        /// <remarks>The 16 first bytes written to <paramref name="cipheredOutput"/> stream are the IV.</remarks>
        public static async Task<T> AesEncryptAsync<T>(this Stream input, T cipheredOutput, byte[] key, byte[] iv, bool leaveOpen = false)
            where T : Stream
        {
            _ = key ?? throw new ArgumentNullException(nameof(key));
            _ = iv ?? throw new ArgumentNullException(nameof(iv));

            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;

            return await input.AesEncryptAsync(cipheredOutput, aes, leaveOpen);
        }

        /// <summary>
        /// Encrypts the content of <paramref name="input"/> stream to the <paramref name="cipheredOutput"/> stream using the <paramref name="aes"/> key and <see cref="Aes"/> algorithm.
        /// </summary>
        /// <typeparam name="T">Type of the output stream.</typeparam>
        /// <param name="input">The input stream whose content is to be ciphered.</param>
        /// <param name="cipheredOutput">The output stream.</param>
        /// <param name="aes">The <see cref="Aes"/> key.</param>
        /// <param name="leaveOpen"><c>true</c> to not close the input stream once the decryption is done, otherwise <c>false</c>.</param>
        /// <returns>The <paramref name="cipheredOutput"/> stream.</returns>
        /// <remarks>The 16 first bytes written to <paramref name="cipheredOutput"/> stream are the IV.</remarks>
        public static async Task<T> AesEncryptAsync<T>(this Stream input, T cipheredOutput, Aes aes, bool leaveOpen = false)
            where T : Stream
        {
            _ = input ?? throw new ArgumentNullException(nameof(input));
            _ = cipheredOutput ?? throw new ArgumentNullException(nameof(cipheredOutput));
            _ = aes ?? throw new ArgumentNullException(nameof(aes));

            await cipheredOutput.WriteAsync(new ReadOnlyMemory<byte>(aes.IV));

            using var encryptor = aes.CreateEncryptor();

            await using var cryptoStream = new CryptoStream(cipheredOutput, encryptor, CryptoStreamMode.Write, leaveOpen);

            await input.CopyToAsync(cryptoStream);

            return cipheredOutput;
        }

        #endregion

        #region >> AesTranscryptAsync

        /// <summary>
        /// Decrypts the content of <paramref name="cipheredInput"/> stream using the <paramref name="key1"/> and encrypts the data again to a new <see cref="MemoryStream"/> using <paramref name="key2"/> and <see cref="Aes"/> algorithm.
        /// </summary>
        /// <param name="cipheredInput">The input stream whose content is ciphered with <paramref name="key1"/>.</param>
        /// <param name="key1">The secret AES key used to decrypt the <paramref name="cipheredInput"/> stream content.</param>
        /// <param name="key2">The secret AES key used to encrypt the data to the returned stream.</param>
        /// <param name="leaveOpen"><c>true</c> to not close the input stream once the transcryption is done, otherwise <c>false</c>.</param>
        /// <returns>The new <see cref="MemoryStream"/> instance.</returns>
        /// <remarks>
        /// The 16 first bytes of the <paramref name="cipheredInput"/> stream must be the IV.
        /// The 16 first bytes written to the returned stream are the IV.
        /// </remarks>
        public static async Task<MemoryStream> AesTranscryptAsync(this Stream cipheredInput, byte[] key1, byte[] key2, bool leaveOpen = false)
        {
            var outputStream = new MemoryStream();

            return await cipheredInput.AesTranscryptAsync(outputStream, key1, key2, leaveOpen);
        }

        /// <summary>
        /// Decrypts the content of <paramref name="cipheredInput"/> stream using the <paramref name="key1"/> and encrypts the data again to <paramref name="cipheredOutput"/> stream using <paramref name="key2"/> and <see cref="Aes"/> algorithm.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="cipheredInput">The input stream whose content is ciphered with <paramref name="key1"/>.</param>
        /// <param name="cipheredOutput">The output stream whose content is ciphered with <paramref name="key2"/>.</param>
        /// <param name="key1">The secret AES key used to decrypt the <paramref name="cipheredInput"/> stream content.</param>
        /// <param name="key2">The secret AES key used to encrypt the data to the <paramref name="cipheredOutput"/> stream.</param>
        /// <param name="leaveOpen"><c>true</c> to not close the input stream once the transcryption is done, otherwise <c>false</c>.</param>
        /// <returns>The <paramref name="cipheredOutput"/> stream.</returns>
        /// <remarks>
        /// The 16 first bytes of the <paramref name="cipheredInput"/> stream must be the IV.
        /// The 16 first bytes written to <paramref name="cipheredOutput"/> stream are the IV.
        /// </remarks>
        public static async Task<T> AesTranscryptAsync<T>(this Stream cipheredInput, T cipheredOutput, byte[] key1, byte[] key2, bool leaveOpen = false)
            where T : Stream
        {
            var iv1 = new byte[16];
            await cipheredInput.ReadAsync(iv1.AsMemory(0, 16));

            using var aes2 = Aes.Create();
            var iv2 = aes2.IV;

            await cipheredOutput.WriteAsync(iv2.AsMemory(0, 16));

            return await cipheredInput.AesTranscryptAsync(cipheredOutput, key1, key2, iv1, iv2, leaveOpen);
        }

        /// <summary>
        /// Decrypts the content of <paramref name="cipheredInput"/> stream using the <paramref name="key1"/> and encrypts the data again to <paramref name="cipheredOutput"/> stream using <paramref name="key2"/> and <see cref="Aes"/> algorithm.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="cipheredInput">The input stream whose content is ciphered with <paramref name="key1"/>.</param>
        /// <param name="cipheredOutput">The output stream whose content is ciphered with <paramref name="key2"/>.</param>
        /// <param name="key1">The secret AES key used to decrypt the <paramref name="cipheredInput"/> stream content.</param>
        /// <param name="key2">The secret AES key used to encrypt the data to the <paramref name="cipheredOutput"/> stream.</param>
        /// <param name="iv1"></param>
        /// <param name="iv2"></param>
        /// <param name="leaveOpen"><c>true</c> to not close the input stream once the transcryption is done, otherwise <c>false</c>.</param>
        /// <returns>The <paramref name="cipheredOutput"/> stream.</returns>
        public static async Task<T> AesTranscryptAsync<T>(this Stream cipheredInput, T cipheredOutput, byte[] key1, byte[] key2, byte[] iv1, byte[] iv2, bool leaveOpen = false)
            where T : Stream
        {
            using var aes1 = Aes.Create();
            aes1.Key = key1;
            aes1.IV = iv1;

            using var aes2 = Aes.Create();
            aes2.Key = key2;
            aes2.IV = iv2;

            return await cipheredInput.AesTranscryptAsync(cipheredOutput, aes1, aes2, leaveOpen);
        }

        /// <summary>
        /// Decrypts the content of <paramref name="cipheredInput"/> stream using the <paramref name="aes1"/> key and encrypts the data again to <paramref name="cipheredOutput"/> stream using <paramref name="aes2"/> key and <see cref="Aes"/> algorithm.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="cipheredInput">The input stream whose content is ciphered with <paramref name="aes1"/>.</param>
        /// <param name="cipheredOutput">The output stream whose content is ciphered with <paramref name="aes2"/>.</param>
        /// <param name="aes1">The secret AES key used to decrypt the <paramref name="cipheredInput"/> stream content.</param>
        /// <param name="aes2">The secret AES key used to encrypt the data to the <paramref name="cipheredOutput"/> stream.</param>
        /// <param name="leaveOpen"><c>true</c> to not close the input stream once the transcryption is done, otherwise <c>false</c>.</param>
        /// <returns>The <paramref name="cipheredOutput"/> stream.</returns>
        public static async Task<T> AesTranscryptAsync<T>(this Stream cipheredInput, T cipheredOutput, Aes aes1, Aes aes2, bool leaveOpen = false)
        where T : Stream
        {
            _ = cipheredInput ?? throw new ArgumentNullException(nameof(cipheredInput));
            _ = cipheredOutput ?? throw new ArgumentNullException(nameof(cipheredOutput));
            _ = aes1 ?? throw new ArgumentNullException(nameof(aes1));
            _ = aes2 ?? throw new ArgumentNullException(nameof(aes2));

            using var key1Decryptor = aes1.CreateDecryptor();

            await using var key1CryptoStream = new CryptoStream(cipheredInput, key1Decryptor, CryptoStreamMode.Read, leaveOpen);

            using var key2Encryptor = aes2.CreateEncryptor();

            await using var key2CryptoStream = new CryptoStream(cipheredOutput, key2Encryptor, CryptoStreamMode.Write, leaveOpen);

            await key1CryptoStream.CopyToAsync(key2CryptoStream);

            return cipheredOutput;
        }

        #endregion
    }
}
