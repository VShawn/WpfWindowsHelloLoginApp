using System;
using System.Threading.Tasks;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.DataProtection;
using Windows.Storage.Streams;

namespace _1RM.Utils.SecurityUtils
{
    /// <summary>
    /// encrypt string to base64, it can be decrypt only by the same local user, it can't be decrypt by other user or other machine
    /// REF: https://learn.microsoft.com/en-us/uwp/api/windows.security.cryptography.dataprotection.dataprotectionprovider?view=winrt-22621
    /// </summary>
    public static class DataProtectionForLocal
    {
        /// <summary>
        /// encrypt string to base64, it can be decrypt only by the same local user
        /// </summary>
        public static async Task<string> ProtectAsync(string strMsg, BinaryStringEncoding encoding = BinaryStringEncoding.Utf8)
        {
            var strDescriptor = "LOCAL=user";
            //String strDescriptor = "LOCAL=machine";
            // Create a DataProtectionProvider object for the specified descriptor.
            var provider = new DataProtectionProvider(strDescriptor);

            // Encode the plaintext input message to a buffer.
            encoding = BinaryStringEncoding.Utf8;
            IBuffer buffMsg = CryptographicBuffer.ConvertStringToBinary(strMsg, encoding);

            // Encrypt the message.
            IBuffer buffProtected = await provider.ProtectAsync(buffMsg);

            // Execution of the ProtectAsync function resumes here
            // after the awaited task (Provider.ProtectAsync) completes.
            var base64 = CryptographicBuffer.EncodeToBase64String(buffProtected);
            return base64;
        }

        public static async Task<string> SampleUnprotectData(IBuffer buffProtected, BinaryStringEncoding encoding = BinaryStringEncoding.Utf8)
        {
            // Create a DataProtectionProvider object.
            DataProtectionProvider Provider = new DataProtectionProvider();

            // Decrypt the protected message specified on input.
            IBuffer buffUnprotected = await Provider.UnprotectAsync(buffProtected);

            // Execution of the SampleUnprotectData method resumes here
            // after the awaited task (Provider.UnprotectAsync) completes
            // Convert the unprotected message from an IBuffer object to a string.
            string strClearText = CryptographicBuffer.ConvertBinaryToString(encoding, buffUnprotected);

            // Return the plaintext string.
            return strClearText;
        }

        public static async Task<string> SampleUnprotectData(string base64, BinaryStringEncoding encoding = BinaryStringEncoding.Utf8)
        {
            var buffProtected = CryptographicBuffer.DecodeFromBase64String(base64);
            if (buffProtected == null)
                return string.Empty;
            return await SampleUnprotectData(buffProtected, encoding);
        }
    }
}
