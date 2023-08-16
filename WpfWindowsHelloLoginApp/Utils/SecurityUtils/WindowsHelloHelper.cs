﻿using System;
using System.Globalization;
using System.Threading.Tasks;
using Windows.Security.Credentials;

namespace _1RM.Utils.SecurityUtils
{
    public class WindowsHelloHelper
    {
        private static readonly string _accountId = DateTime.Now.ToString(CultureInfo.InvariantCulture);


        public static bool IsOsSupported => WindowsVersionHelper.IsLowerThanWindows10() == false;

        public static async Task<bool> HelloIsAvailable()
        {
            if (IsOsSupported == false)
            {
                return true;
            }

            var isAvailable = await KeyCredentialManager.IsSupportedAsync();
            return isAvailable;
        }

        //public static async Task<bool?> HelloVerifyAsyncIfIsSupport(bool defaultReturn = true)
        //{
        //    if (WindowsHelloHelper.IsOsSupported)
        //    {
        //        if (await WindowsHelloHelper.HelloIsAvailable() == true)
        //        {
        //            return await HelloVerifyAsync();
        //        }
        //    }
        //    return defaultReturn;
        //}

        public static async Task<bool?> HelloVerifyAsync()
        {
            if (IsOsSupported == false)
            {
                return true;
            }

            var isAvailable = await KeyCredentialManager.IsSupportedAsync();
            if (isAvailable)
            {
                //var consentResult = await UserConsentVerifier.RequestVerificationAsync(message);
                //switch (consentResult)
                //{
                //    case UserConsentVerificationResult.Verified:
                //        return true;
                //    case UserConsentVerificationResult.Canceled:
                //        return null;
                //    case UserConsentVerificationResult.DeviceNotPresent:
                //    case UserConsentVerificationResult.NotConfiguredForUser:
                //    case UserConsentVerificationResult.DisabledByPolicy:
                //    case UserConsentVerificationResult.DeviceBusy:
                //    case UserConsentVerificationResult.RetriesExhausted:
                //    default:
                //        break;
                //}
                //return false;


                var result = await KeyCredentialManager.RequestCreateAsync(_accountId + "-UserConsentVerifier", KeyCredentialCreationOption.ReplaceExisting);
                switch (result.Status)
                {
                    case KeyCredentialStatus.Success:
                        return true;
                    case KeyCredentialStatus.UserCanceled:
                        return null;
                    case KeyCredentialStatus.UnknownError:
                    case KeyCredentialStatus.NotFound:
                    case KeyCredentialStatus.UserPrefersPassword:
                    case KeyCredentialStatus.CredentialAlreadyExists:
                    case KeyCredentialStatus.SecurityDeviceLocked:
                    default:
                        return false;
                }
            }
            return false;
        }

    }
}
