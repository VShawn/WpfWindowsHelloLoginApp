using Windows.Security.Credentials;

namespace _1RM.Utils.SecurityUtils.PasswordVaultManager
{
    /// <summary>
    /// Ref: https://learn.microsoft.com/en-us/windows/uwp/security/credential-locker
    /// </summary>
    internal class PasswordVaultManagerWindowsApi : IPasswordManager
    {
        private const string ResourceName = "1Remote";
        string IPasswordManager.Retrieve(string key)
        {
            var vault = new PasswordVault();
            var credential = vault.Retrieve(ResourceName, key);
            return credential.Password;
        }

        void IPasswordManager.Add(string key, string password)
        {
            var vault = new PasswordVault();
            vault.Add(new PasswordCredential(ResourceName, key, password));
        }
    }
}
