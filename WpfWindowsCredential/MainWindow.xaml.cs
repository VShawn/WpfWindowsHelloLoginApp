using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
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
using Microsoft.Win32.SafeHandles;
using Misuzilla.Security;
using static Misuzilla.Security.CredentialUI;

namespace WpfWindowsCredential
{
    /// <summary>
    /// http://www.pinvoke.net/default.aspx/advapi32.logonuser
    /// </summary>
    internal class NativeMethods
    {
        public enum LogonTypes : int
        {
            /// <summary>
            /// This logon type is intended for users who will be interactively using the computer, such as a user being logged on  
            /// by a terminal server, remote shell, or similar process.
            /// This logon type has the additional expense of caching logon information for disconnected operations; 
            /// therefore, it is inappropriate for some client/server applications,
            /// such as a mail server.
            /// </summary>
            LOGON32_LOGON_INTERACTIVE = 2,

            /// <summary>
            /// This logon type is intended for high performance servers to authenticate plaintext passwords.

            /// The LogonUser function does not cache credentials for this logon type.
            /// </summary>
            LOGON32_LOGON_NETWORK = 3,

            /// <summary>
            /// This logon type is intended for batch servers, where processes may be executing on behalf of a user without 
            /// their direct intervention. This type is also for higher performance servers that process many plaintext
            /// authentication attempts at a time, such as mail or Web servers. 
            /// The LogonUser function does not cache credentials for this logon type.
            /// </summary>
            LOGON32_LOGON_BATCH = 4,

            /// <summary>
            /// Indicates a service-type logon. The account provided must have the service privilege enabled. 
            /// </summary>
            LOGON32_LOGON_SERVICE = 5,

            /// <summary>
            /// This logon type is for GINA DLLs that log on users who will be interactively using the computer. 
            /// This logon type can generate a unique audit record that shows when the workstation was unlocked. 
            /// </summary>
            LOGON32_LOGON_UNLOCK = 7,

            /// <summary>
            /// This logon type preserves the name and password in the authentication package, which allows the server to make 
            /// connections to other network servers while impersonating the client. A server can accept plaintext credentials 
            /// from a client, call LogonUser, verify that the user can access the system across the network, and still 
            /// communicate with other servers.
            /// NOTE: Windows NT:  This value is not supported. 
            /// </summary>
            LOGON32_LOGON_NETWORK_CLEARTEXT = 8,

            /// <summary>
            /// This logon type allows the caller to clone its current token and specify new credentials for outbound connections.
            /// The new logon session has the same local identifier but uses different credentials for other network connections. 
            /// NOTE: This logon type is supported only by the LOGON32_PROVIDER_WINNT50 logon provider.
            /// NOTE: Windows NT:  This value is not supported. 
            /// </summary>
            LOGON32_LOGON_NEW_CREDENTIALS = 9,
        }

        public enum LogonProvider : int
        {
            /// <summary>
            /// Use the standard logon provider for the system. 
            /// The default security provider is negotiate, unless you pass NULL for the domain name and the user name 
            /// is not in UPN format. In this case, the default provider is NTLM. 
            /// NOTE: Windows 2000/NT:   The default security provider is NTLM.
            /// </summary>
            LOGON32_PROVIDER_DEFAULT = 0,
            LOGON32_PROVIDER_WINNT35 = 1,
            LOGON32_PROVIDER_WINNT40 = 2,
            LOGON32_PROVIDER_WINNT50 = 3
        }
        public enum SecurityImpersonationLevel : int
        {
            /// <summary>
            /// The server process cannot obtain identification information about the client, 
            /// and it cannot impersonate the client. It is defined with no value given, and thus, 
            /// by ANSI C rules, defaults to a value of zero. 
            /// </summary>
            SecurityAnonymous = 0,

            /// <summary>
            /// The server process can obtain information about the client, such as security identifiers and privileges, 
            /// but it cannot impersonate the client. This is useful for servers that export their own objects, 
            /// for example, database products that export tables and views. 
            /// Using the retrieved client-security information, the server can make access-validation decisions without 
            /// being able to use other services that are using the client's security context. 
            /// </summary>
            SecurityIdentification = 1,

            /// <summary>
            /// The server process can impersonate the client's security context on its local system. 
            /// The server cannot impersonate the client on remote systems. 
            /// </summary>
            SecurityImpersonation = 2,

            /// <summary>
            /// The server process can impersonate the client's security context on remote systems. 
            /// NOTE: Windows NT:  This impersonation level is not supported.
            /// </summary>
            SecurityDelegation = 3,
        }

        /// <summary>
        /// https://github.com/Alachisoft/NosDB/blob/master/Src/Common/Security/SafeTokenHandle.cs
        /// https://github.com/mvelazc0/PurpleSharp/blob/master/PurpleSharp/Lib/Impersonator.cs
        /// </summary>
        public sealed class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            private SafeTokenHandle() : base(true) { }

            [DllImport("kernel32.dll")]
            [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
            [SuppressUnmanagedCodeSecurity]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool CloseHandle(IntPtr handle);

            protected override bool ReleaseHandle()
            {
                if (handle == IntPtr.Zero)
                {
                    return true;
                }
                var ret = CloseHandle(handle);
                handle = IntPtr.Zero;
                return ret;
            }
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LogonUser(String lpszUsername, String lpszDomain, String lpszPassword, LogonTypes dwLogonType, LogonProvider dwLogonProvider, out SafeTokenHandle phToken);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LogonUser(String lpszUsername, String lpszDomain, IntPtr phPassword, LogonTypes dwLogonType, LogonProvider dwLogonProvider, out SafeTokenHandle phToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool DuplicateToken(SafeTokenHandle ExistingTokenHandle, SecurityImpersonationLevel SECURITY_IMPERSONATION_LEVEL, out SafeTokenHandle DuplicateTokenHandle);

    }

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
            if (ret != null)
                MessageBox.Show($"{ret.UserName} \r\n {ret.Password} \r\n {ret.DomainName} \r\n {ret.IsSaveChecked}");
        }

        private void Button_OnClickPromptForWindowsCredentials(object sender, RoutedEventArgs e)
        {
            var ret = CredentialUI.PromptForWindowsCredentials("caption", "tes message");
            if (ret != null)
            {
                string userName = ret.UserName;
                string userPassword = ret.Password;
                string domain = ret.DomainName;
                // Call LogonUser to obtain a handle to an access token. 
                bool returnValue = NativeMethods.LogonUser(userName, domain, userPassword,
                    NativeMethods.LogonTypes.LOGON32_LOGON_INTERACTIVE, NativeMethods.LogonProvider.LOGON32_PROVIDER_DEFAULT,
                    out var tokenHandle);
                if (returnValue)
                {
                    tokenHandle.Dispose();

                    //using (tokenHandle)
                    //{
                    //    //// Use the token handle returned by LogonUser. 
                    //    //using (WindowsImpersonationContext impersonatedUser = WindowsIdentity.Impersonate(safeTokenHandle.DangerousGetHandle()))
                    //    //{
                    //    //    var sourceGenerator = new Generator.SolutionAnalayzer(solutionPath);
                    //    //    var workspaceModel = sourceGenerator.BuildWorkspaceModel(repoRootPath);
                    //    //    return workspaceModel;
                    //    //}
                    //    //// Releasing the context object stops the impersonation 
                    //}
                    MessageBox.Show($"{ret.UserName} \r\n {ret.Password} \r\n {ret.DomainName} \r\n {ret.IsSaveChecked}");
                }
                else
                {
                    int err = Marshal.GetLastWin32Error();
                    MessageBox.Show(err.ToString("X"));
                }
            }
        }

        private void Button_OnClickPrompt(object sender, RoutedEventArgs e)
        {
            var ret = CredentialUI.Prompt("caption", "tes message");
            if (ret != null)
                MessageBox.Show($"{ret.UserName} \r\n {ret.Password} \r\n {ret.DomainName} \r\n {ret.IsSaveChecked}");
        }
        private void Button_OnClickPromptForCredentialsWithSecureString(object sender, RoutedEventArgs e)
        {
            var ret = CredentialUI.PromptForCredentialsWithSecureString("target name", "caption", "tes message");
            if (ret != null)
                MessageBox.Show($"{ret.UserName} \r\n {ret.Password} \r\n {ret.DomainName} \r\n {ret.IsSaveChecked}");
        }
        private void Button_OnClickPromptForWindowsCredentialsWithSecureString(object sender, RoutedEventArgs e)
        {
            var ret = CredentialUI.PromptForWindowsCredentialsWithSecureString("caption", "tes message");
            if (ret != null)
                MessageBox.Show($"{ret.UserName} \r\n {ret.Password} \r\n {ret.DomainName} \r\n {ret.IsSaveChecked}");
        }


        private async void ButtonLoginWithPass_OnClick(object sender, RoutedEventArgs e)
        {
            InitializeComponent();

            // Declare/initialize variables.
            bool save = false;
            int errorcode = 0;
            uint dialogReturn;
            uint authPackage = 0;
            IntPtr outCredBuffer;
            uint outCredSize;

            // Create the CREDUI_INFO struct.
            CREDUI_INFO credui = new CREDUI_INFO();
            credui.cbSize = Marshal.SizeOf(credui);
            credui.pszCaptionText = "Connect to your application";
            credui.pszMessageText = "Enter your credentials!";
            credui.hwndParent = new WindowInteropHelper(this).Handle;

            // Show the dialog.
            dialogReturn = CredUIPromptForWindowsCredentials(
                ref credui,
                errorcode,
                ref authPackage,
                (IntPtr)0,  // You can force that a specific username is shown in the dialog. Create it with 'CredPackAuthenticationBuffer()'. Then, the buffer goes here...
                0,          // ...and the size goes here. You also have to add CREDUIWIN_IN_CRED_ONLY to the flags (last argument).
                out outCredBuffer,
                out outCredSize,
                ref save,
                0); // Use the PromptForWindowsCredentialsFlags Enum here. You can use multiple flags if you seperate them with | .

            if (dialogReturn == 1223) // Result of 1223 means the user canceled. Not sure if other errors are ever returned.
                MessageBox.Show("User cancelled!");
            if (dialogReturn != 0) // Result of something other than 0 means...something, I'm sure. Either way, failed or canceled.
                return;

            var domain = new StringBuilder(100);
            var username = new StringBuilder(100);
            var password = new StringBuilder(100);
            int maxLength = 100; // Note that you can have different max lengths for each variable if you want.

            // Unpack the info from the buffer.
            CredUnPackAuthenticationBuffer(0, outCredBuffer, outCredSize, username, ref maxLength, domain, ref maxLength, password, ref maxLength);

            // Clear the memory allocated by CredUIPromptForWindowsCredentials.
            CoTaskMemFree(outCredBuffer);

            // Output info, escaping whitespace characters for the password.
            string ret = "";
            ret += String.Format("Domain: {0}\n", domain);
            ret += String.Format("Username: {0}\n", username);
            ret += String.Format("Password (hashed): {0}\n", EscapeString(password.ToString()));
            MessageBox.Show(ret);
        }


        public static string EscapeString(string s)
        {
            // Formatted like this only for you, SO.
            return s
                .Replace("\a", "\\a")
                .Replace("\b", "\\b")
                .Replace("\f", "\\f")
                .Replace("\n", "\\n")
                .Replace("\r", "\\r")
                .Replace("\t", "\\t")
                .Replace("\v", "\\v");
        }

        #region DLLImports
        [DllImport("ole32.dll")]
        public static extern void CoTaskMemFree(IntPtr ptr);

        [DllImport("credui.dll", CharSet = CharSet.Unicode)]
        private static extern uint CredUIPromptForWindowsCredentials(ref CREDUI_INFO notUsedHere, int authError, ref uint authPackage, IntPtr InAuthBuffer,
          uint InAuthBufferSize, out IntPtr refOutAuthBuffer, out uint refOutAuthBufferSize, ref bool fSave, PromptForWindowsCredentialsFlags flags);

        [DllImport("credui.dll", CharSet = CharSet.Unicode)]
        private static extern bool CredUnPackAuthenticationBuffer(int dwFlags, IntPtr pAuthBuffer, uint cbAuthBuffer, StringBuilder pszUserName, ref int pcchMaxUserName, StringBuilder pszDomainName, ref int pcchMaxDomainame, StringBuilder pszPassword, ref int pcchMaxPassword);
        #endregion

        #region Structs and Enums
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CREDUI_INFO
        {
            public int cbSize;
            public IntPtr hwndParent;
            public string pszMessageText;
            public string pszCaptionText;
            public IntPtr hbmBanner;
        }

        private enum PromptForWindowsCredentialsFlags
        {
            /// <summary>
            /// The caller is requesting that the credential provider return the user name and password in plain text.
            /// This value cannot be combined with SECURE_PROMPT.
            /// </summary>
            CREDUIWIN_GENERIC = 0x1,
            /// <summary>
            /// The Save check box is displayed in the dialog box.
            /// </summary>
            CREDUIWIN_CHECKBOX = 0x2,
            /// <summary>
            /// Only credential providers that support the authentication package specified by the authPackage parameter should be enumerated.
            /// This value cannot be combined with CREDUIWIN_IN_CRED_ONLY.
            /// </summary>
            CREDUIWIN_AUTHPACKAGE_ONLY = 0x10,
            /// <summary>
            /// Only the credentials specified by the InAuthBuffer parameter for the authentication package specified by the authPackage parameter should be enumerated.
            /// If this flag is set, and the InAuthBuffer parameter is NULL, the function fails.
            /// This value cannot be combined with CREDUIWIN_AUTHPACKAGE_ONLY.
            /// </summary>
            CREDUIWIN_IN_CRED_ONLY = 0x20,
            /// <summary>
            /// Credential providers should enumerate only administrators. This value is intended for User Account Control (UAC) purposes only. We recommend that external callers not set this flag.
            /// </summary>
            CREDUIWIN_ENUMERATE_ADMINS = 0x100,
            /// <summary>
            /// Only the incoming credentials for the authentication package specified by the authPackage parameter should be enumerated.
            /// </summary>
            CREDUIWIN_ENUMERATE_CURRENT_USER = 0x200,
            /// <summary>
            /// The credential dialog box should be displayed on the secure desktop. This value cannot be combined with CREDUIWIN_GENERIC.
            /// Windows Vista: This value is not supported until Windows Vista with SP1.
            /// </summary>
            CREDUIWIN_SECURE_PROMPT = 0x1000,
            /// <summary>
            /// The credential provider should align the credential BLOB pointed to by the refOutAuthBuffer parameter to a 32-bit boundary, even if the provider is running on a 64-bit system.
            /// </summary>
            CREDUIWIN_PACK_32_WOW = 0x10000000,
        }
        #endregion
    }
}
