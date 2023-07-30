using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
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
                        MessageBox.Show("Logged in.");
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
    }


}
