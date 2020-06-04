using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace Microsoft.Pfe.GetUserRights
{
    /// <summary>
    /// The LSA_UNICODE_STRING structure is used by various Local Security Authority (LSA) functions to specify a Unicode string.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct LSA_UNICODE_STRING
    {
        public UInt16 Length;
        public UInt16 MaximumLength;
        public IntPtr Buffer;

        public void SetTo(string str)
        {
            Buffer = Marshal.StringToHGlobalUni(str);
            Length = (UInt16)(str.Length * UnicodeEncoding.CharSize);
            MaximumLength = (UInt16)(Length + UnicodeEncoding.CharSize);
        }

        public override string ToString()
        {
            string str = Marshal.PtrToStringUni(Buffer, Length / UnicodeEncoding.CharSize);
            return str;
        }

        public void Clean()
        {
            if (Buffer != IntPtr.Zero)
                Marshal.FreeHGlobal(Buffer);
            Buffer = IntPtr.Zero;
            Length = 0;
            MaximumLength = 0;
        }
    }

    /// <summary>
    /// The LSA_OBJECT_ATTRIBUTES structure is used with the LsaOpenPolicy function to specify the attributes of the connection to the Policy object.
    /// When you call LsaOpenPolicy, initialize the members of this structure to NULL or zero because the function does not use the information.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct LSA_OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public LSA_UNICODE_STRING ObjectName;
        public UInt32 Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    /// <summary>
    /// Flags for ACCESS_MASK
    /// The ACCESS_MASK data type is a DWORD value that defines standard, specific, and generic rights. 
    /// These rights are used in access control entries (ACEs) and are the primary means 
    /// of specifying the requested or granted access to an object.
    /// </summary>
    [Flags]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores", Justification = "<Pending>")]
    public enum LSA_AccessPolicies : long
    {
        POLICY_VIEW_LOCAL_INFORMATION = 0x00000001L,
        POLICY_VIEW_AUDIT_INFORMATION = 0x00000002L,
        POLICY_GET_PRIVATE_INFORMATION = 0x00000004L,
        POLICY_TRUST_ADMIN = 0x00000008L,
        POLICY_CREATE_ACCOUNT = 0x00000010L,
        POLICY_CREATE_SECRET = 0x00000020L,
        POLICY_CREATE_PRIVILEGE = 0x00000040L,
        POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x00000080L,
        POLICY_SET_AUDIT_REQUIREMENTS = 0x00000100L,
        POLICY_AUDIT_LOG_ADMIN = 0x00000200L,
        POLICY_SERVER_ADMIN = 0x00000400L,
        POLICY_LOOKUP_NAMES = 0x00000800L,
        POLICY_NOTIFICATION = 0x00001000L
    }

    /// <summary>
    /// The SID_NAME_USE enumeration contains values that specify the type of a security identifier (SID)
    /// </summary>
    enum SID_NAME_USE
    {
        SidTypeUser = 1,
        SidTypeGroup,
        SidTypeDomain,
        SidTypeAlias,
        SidTypeWellKnownGroup,
        SidTypeDeletedAccount,
        SidTypeInvalid,
        SidTypeUnknown,
        SidTypeComputer
    }

    public static class PolicyReader
    {
        static uint aWinErrorCode = 0; //contains the last error


        /// <summary>
        /// Calls LsaEnumerateAccountRights to enumerate user rights
        /// </summary>
        /// <param name="userName">Account name in fully qualified string in the domain_name\user_name format</param>
        /// <returns>IEnumerable strings of user rights</returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "IDE0059:Unnecessary assignment of a value", Justification = "<Pending>")]
        public static IEnumerable<string> GetUserRights(string userName)
        {
            //initialize an empty unicode-string
            LSA_UNICODE_STRING aSystemName = new LSA_UNICODE_STRING();
            //combine all policies
            uint aAccess = (uint)(
                LSA_AccessPolicies.POLICY_AUDIT_LOG_ADMIN |
                LSA_AccessPolicies.POLICY_CREATE_ACCOUNT |
                LSA_AccessPolicies.POLICY_CREATE_PRIVILEGE |
                LSA_AccessPolicies.POLICY_CREATE_SECRET |
                LSA_AccessPolicies.POLICY_GET_PRIVATE_INFORMATION |
                LSA_AccessPolicies.POLICY_LOOKUP_NAMES |
                LSA_AccessPolicies.POLICY_NOTIFICATION |
                LSA_AccessPolicies.POLICY_SERVER_ADMIN |
                LSA_AccessPolicies.POLICY_SET_AUDIT_REQUIREMENTS |
                LSA_AccessPolicies.POLICY_SET_DEFAULT_QUOTA_LIMITS |
                LSA_AccessPolicies.POLICY_TRUST_ADMIN |
                LSA_AccessPolicies.POLICY_VIEW_AUDIT_INFORMATION |
                LSA_AccessPolicies.POLICY_VIEW_LOCAL_INFORMATION
                );
            //initialize a pointer for the policy handle
            IntPtr aPolicyHandle = IntPtr.Zero;

            //these attributes are not used, but LsaOpenPolicy wants them to exists
            LSA_OBJECT_ATTRIBUTES aObjectAttributes = new LSA_OBJECT_ATTRIBUTES
            {
                Length = 0,
                RootDirectory = IntPtr.Zero,
                Attributes = 0,
                SecurityDescriptor = IntPtr.Zero,
                SecurityQualityOfService = IntPtr.Zero
            };

            //get a policy handle
            uint aOpenPolicyResult = NativeMethods.LsaOpenPolicy(ref aSystemName, ref aObjectAttributes, aAccess, out aPolicyHandle);
            aWinErrorCode = NativeMethods.LsaNtStatusToWinError(aOpenPolicyResult);
            if (aWinErrorCode == Win32Constants.ERROR_SUCCESS) // We opened Policy with success
            {
                // Get principal SID
                byte[] sid = GetSID(userName);

                if (sid != null) // If we got SID
                {
                    // Call LsaEnumerateAccountRights
                    _ = NativeMethods.LsaEnumerateAccountRights(aPolicyHandle, sid, out IntPtr rightsPtr, out uint countOfRights);
                    try
                    {
                        IntPtr ptr = rightsPtr;
                        for (Int32 i = 0; i < countOfRights; i++)
                        {
                            // Get Result
                            //LSA_UNICODE_STRING structure = new LSA_UNICODE_STRING();
                            LSA_UNICODE_STRING structure = (LSA_UNICODE_STRING)Marshal.PtrToStructure(ptr, typeof(LSA_UNICODE_STRING));

                            char[] destination = new char[structure.Length / sizeof(char)];
                            Marshal.Copy(structure.Buffer, destination, 0, destination.Length);

                            string userRightStr = new string(destination, 0, destination.Length);

                            yield return userRightStr;

                            // Move pointer to the next string
                            ptr = (IntPtr)(((long)ptr) + Marshal.SizeOf(typeof(LSA_UNICODE_STRING)));
                        }
                    }
                    finally
                    {
                        _ = NativeMethods.LsaFreeMemory(rightsPtr);
                    }
                }
            }
        }

        /// <summary>
        /// Enumerates all rights assigned to user, directly or through group membership
        /// </summary>
        /// <param name="principal">User or Group Account name in the domain_name\user_name format</param>
        /// <returns>IEnumerable strings of security principal rights</returns>
        public static IEnumerable<string> GetAllRights(string principal)
        {
            HashSet<string> rights = new HashSet<string>();

            // Get rights for principal
            foreach (string right in GetUserRights(principal))
                rights.Add(right);

            // Enumerate groups where principal belongs
            foreach (string group in Utils.GetUserMembership(principal))
            {
                // Get rights assigned to Group
                foreach (string right in GetUserRights(group))
                    rights.Add(right);
            }

            // Return result
            return rights.AsEnumerable();
        }


        /// <summary>
        /// Calls LookupAccountName to get User or Group SID
        /// </summary>
        /// <param name="accountName">User or Group Account name in the domain_name\user_name format</param>
        /// <returns>SID</returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "IDE0059:Unnecessary assignment of a value", Justification = "<Pending>")]
        private static byte[] GetSID(string accountName)
        {
            // Declare and initialize parameters
            byte[] Sid = null;
            uint cbSid = 0;
            StringBuilder referencedDomainName = new StringBuilder();
            uint cchReferencedDomainName = (uint)referencedDomainName.Capacity;

            int err = Win32Constants.ERROR_SUCCESS;

            // Call LookupAccountName
            if (!NativeMethods.LookupAccountName(null, accountName, Sid, ref cbSid, referencedDomainName, ref cchReferencedDomainName, out SID_NAME_USE sidUse))
            {
                err = Marshal.GetLastWin32Error();
                if (err == Win32Constants.ERROR_INSUFFICIENT_BUFFER || err == Win32Constants.ERROR_INVALID_FLAGS)
                {
                    // In case of ERROR_INSUFFICIENT_BUFFER error try again
                    Sid = new byte[cbSid];
                    referencedDomainName.EnsureCapacity((int)cchReferencedDomainName);
                    err = Win32Constants.ERROR_SUCCESS;
                    if (!NativeMethods.LookupAccountName(null, accountName, Sid, ref cbSid, referencedDomainName, ref cchReferencedDomainName, out sidUse))
                        err = Marshal.GetLastWin32Error();
                }
            }
            else
            {
                throw new Exception(String.Format(CultureInfo.CurrentCulture, "PInvoke Error Code {0}", err));
            }
            if (err == 0)
            {
                return Sid;
            }
            else
                return null;
        }
    }
}
