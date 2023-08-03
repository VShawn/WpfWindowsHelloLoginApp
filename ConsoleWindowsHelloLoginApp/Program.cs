using System;
using System.Threading.Tasks;
using Windows.Security.Credentials;

namespace ConsoleWindowsHelloLoginApp
{
    internal class Program
    {
        static async Task<int> Main(string[] args)
        {
            Console.WriteLine("Hello, World!");
            await ButtonLogin_OnClick();
            return 1;
        }


        private static async Task<int> ButtonLogin_OnClick()
        {
            bool supported = await KeyCredentialManager.IsSupportedAsync();
            if (supported)
            {
                var result = await KeyCredentialManager.RequestCreateAsync("login", KeyCredentialCreationOption.ReplaceExisting);
                switch (result.Status)
                {
                    case KeyCredentialStatus.Success:
                        var resourceName = "My App";
                        Windows.Security.Credentials.PasswordCredential? pass = null;
                        var vault = new Windows.Security.Credentials.PasswordVault();
                        try
                        {
                            //var credentialList = vault.FindAllByResource(resourceName);
                            //if (credentialList?.Any() == true)
                            //{
                            //    var credential = credentialList[0];
                            //    credential.RetrievePassword();
                            //    Console.WriteLine(credential?.Password ?? "null");
                            //}
                            pass = vault.Retrieve(resourceName, "last time");
                        }
                        catch (Exception)
                        {
                        }
                        vault.Add(new Windows.Security.Credentials.PasswordCredential(resourceName, "last time", DateTime.Now.ToString("R")));
                        Console.WriteLine("Logged in." + " last pass = " + pass?.Password ?? "null");
                        break;
                    case KeyCredentialStatus.UserCanceled:
                        Console.WriteLine("Login cancelled.");
                        break;
                    case KeyCredentialStatus.UnknownError:
                    case KeyCredentialStatus.NotFound:
                    case KeyCredentialStatus.UserPrefersPassword:
                    case KeyCredentialStatus.CredentialAlreadyExists:
                    case KeyCredentialStatus.SecurityDeviceLocked:
                    default:
                        Console.WriteLine("Login failed.");
                        break;
                }
            }
            else
            {
                Console.WriteLine("Microsoft Passport is not setup!\nPlease go to Windows Settings and set up a PIN to use it.");
            }

            return 1;
        }
    }
}