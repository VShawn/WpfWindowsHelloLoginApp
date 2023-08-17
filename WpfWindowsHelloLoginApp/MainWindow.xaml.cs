using System;
using System.Windows;
using System.Windows.Interop;
using _1RM.Utils.WindowsApi.Credential;
using _1RM.Utils.WindowsSdk;
using _1RM.Utils.WindowsSdk.PasswordVaultManager;
using Windows.Security.Credentials;

namespace WpfWindowsHelloLoginApp
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            User.Text = CredentialPrompt.GetUserName();
        }

        private async void ButtonLogin_OnClick(object sender, RoutedEventArgs e)
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
                            //    MessageBox.Show(credential?.Password ?? "null");
                            //}
                            pass = vault.Retrieve(resourceName, "last time");
                        }
                        catch (Exception)
                        {
                        }

                        vault.Add(new Windows.Security.Credentials.PasswordCredential(resourceName, "last time", DateTime.Now.ToString("R")));
                        MessageBox.Show("Logged in." + " last pass = " + pass?.Password ?? "null");
                        break;
                    case KeyCredentialStatus.UserCanceled:
                        MessageBox.Show("Login cancelled.");
                        break;
                    case KeyCredentialStatus.UnknownError:
                    case KeyCredentialStatus.NotFound:
                    case KeyCredentialStatus.UserPrefersPassword:
                    case KeyCredentialStatus.CredentialAlreadyExists:
                    case KeyCredentialStatus.SecurityDeviceLocked:
                    default:
                        MessageBox.Show("Login failed.");
                        break;
                }
            }
            else
            {
                MessageBox.Show("Microsoft Passport is not setup!\nPlease go to Windows Settings and set up a PIN to use it.");
            }
        }




        private async void ButtonLoginWithPass_OnClick(object sender, RoutedEventArgs e)
        {
            if (CredentialPrompt.LogonUserWithWindowsCredential("验证你的账户", "请输入当前Windows的凭据", 
                    new WindowInteropHelper(this).Handle,
                    null, null,
                    0
                    | (uint)CredentialPrompt.PromptForWindowsCredentialsFlag.CREDUIWIN_GENERIC
                    | (uint)CredentialPrompt.PromptForWindowsCredentialsFlag.CREDUIWIN_ENUMERATE_CURRENT_USER
                    ) == CredentialPrompt.LogonUserStatus.Success)
            {
                MessageBox.Show("验证成功");
            }
            else
            {
                MessageBox.Show("失败");
            }

            //var result = WindowsCredentialHelper.PromptForWindowsCredentials("Hi", "body", new WindowInteropHelper(this).Handle);
            //if (result?.HasNoError == true)
            //{
            //    MessageBox.Show($"输入的信息：\r\n  {result.UserName} \r\n {result.Password} \r\n {result.DomainName} \r\n {result.IsSaveChecked}");
            //}
            //else
            //{
            //    MessageBox.Show("密码未输入完成");
            //}
        }

        private void ButtonBase_OnClick(object sender, RoutedEventArgs e)
        {
            if (CredentialPrompt.LogonUser(User.Text, Pass.Text) == CredentialPrompt.LogonUserStatus.Success)
            {
                MessageBox.Show("验证成功");
            }
            else
            {
                MessageBox.Show("失败");
            }
        }

        private void ButtonReadValue(object sender, RoutedEventArgs e)
        {
            var p = new PasswordVaultManagerWindowsApi("My App");
            TbPasswordVault.Text = (p.Retrieve("test") ?? "null");
        }

        private void ButtonWriteVault(object sender, RoutedEventArgs e)
        {
            var @new = TbPasswordVault.Text;
            var p = new PasswordVaultManagerWindowsApi("My App");
            var last = p.Retrieve("test") ?? "null";
            p.Add("test", @new);
            MessageBox.Show("Logged in." + " last = " + last + ", this = " + @new);
        }


        private async void ButtonProtect_OnClick(object sender, RoutedEventArgs e)
        {
            var p = await DataProtectionForLocal.Protect(Pass.Text);
            Pass.Text = p;
        }
        private async void ButtonUnProtect_OnClick(object sender, RoutedEventArgs e)
        {
            var s = await DataProtectionForLocal.Unprotect(Pass.Text);
            Pass.Text = s;
        }

        private void ButtonReadValueFromCredentialManagement(object sender, RoutedEventArgs e)
        {
            var c = new Credential()
            {
                Type = Credential.CredentialTypeEnum.Generic,
                PersistType = Credential.PersistTypeEnum.LocalComputer,
                Target = "1Remote_" + "flag",
            };
            if (c.Load())
                TbCMValue.Text = c.Password;
            else
                TbCMValue.Text = "null";
        }

        private void ButtonWriteVaultFromCredentialManagement(object sender, RoutedEventArgs e)
        {
            var c = new Credential()
            {
                Target = "1Remote_" + "flag",
                Type = Credential.CredentialTypeEnum.Generic,
                Username = TbCMValue.Text,
                Password = TbCMValue.Text,
                PersistType = Credential.PersistTypeEnum.LocalComputer
            };
            if (!c.Save())
            {
                MessageBox.Show("Failed");
            }
        }
    }
}
