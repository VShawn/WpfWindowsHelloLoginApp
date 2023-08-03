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
using Misuzilla.Security;
using static Misuzilla.Security.CredentialUI;

namespace WpfWindowsCredential
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

        private void Button_OnClickPromptForCredentials(object sender, RoutedEventArgs e)
        {
            var ret = CredentialUI.PromptForCredentials("target name", "test", "tes message");
        }

        private void Button_OnClickPromptForWindowsCredentials(object sender, RoutedEventArgs e)
        {
            var ret = CredentialUI.PromptForWindowsCredentials("caption", "tes message");
        }

        private void Button_OnClickPrompt(object sender, RoutedEventArgs e)
        {
            var ret = CredentialUI.Prompt("caption", "tes message");
        }
        private void Button_OnClickPromptForCredentialsWithSecureString(object sender, RoutedEventArgs e)
        {
            var ret = CredentialUI.PromptForCredentialsWithSecureString("target name", "caption", "tes message");
        }
        private void Button_OnClickPromptForWindowsCredentialsWithSecureString(object sender, RoutedEventArgs e)
        {
            var ret = CredentialUI.PromptForWindowsCredentialsWithSecureString("caption", "tes message");
        }
    }
}
