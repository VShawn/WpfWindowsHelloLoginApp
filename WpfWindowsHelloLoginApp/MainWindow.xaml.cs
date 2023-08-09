using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using Windows.Security.Credentials;
using WpfWindowsHelloLoginApp.CredentialUI;

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
            if (WindowsCredentialHelper.LogonUserWithWindowsCredential("验证你的账户", "请输入当前Windows的凭据", 
                    new WindowInteropHelper(this).Handle,
                    User.Text, Pass.Text,
                    WindowsCredentialHelper.PromptForWindowsCredentialsFlag.CREDUIWIN_ENUMERATE_CURRENT_USER
                    ) == WindowsCredentialHelper.LogonUserStatus.Success)
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
            if (WindowsCredentialHelper.LogonUser(User.Text, Pass.Text) == WindowsCredentialHelper.LogonUserStatus.Success)
            {
                MessageBox.Show("验证成功");
            }
            else
            {
                MessageBox.Show("失败");
            }
        }
    }
}
