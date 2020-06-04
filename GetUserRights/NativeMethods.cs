using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Pfe.GetUserRights
{
    internal static class NativeMethods
    {
        /// <summary>
        /// The LsaOpenPolicy function opens a handle to the Policy object on a local or remote system.
        /// You must run the process "As Administrator" so that the call doesn't fail with ERROR_ACCESS_DENIED.
        /// </summary>
        /// <param name="SystemName">
        ///     A pointer to an LSA_UNICODE_STRING structure that contains the name of the target system. 
        ///     The name can have the form "ComputerName" or "\ComputerName". 
        ///     If this parameter is NULL, the function opens the Policy object on the local system.
        /// </param>
        /// <param name="ObjectAttributes">
        ///     A pointer to an LSA_OBJECT_ATTRIBUTES structure that specifies the connection attributes. 
        ///     The structure members are not used; initialize them to NULL or zero.
        /// </param>
        /// <param name="DesiredAccess">An ACCESS_MASK that specifies the requested access rights.</param>
        /// <param name="PolicyHandle">
        ///     A pointer to an LSA_HANDLE variable that receives a handle to the Policy object.
        ///     When you no longer need this handle, pass it to the LsaClose function to close it.
        /// </param>
        /// <returns>
        ///     If the function succeeds, the function returns STATUS_SUCCESS.
        ///     If the function fails, it returns an NTSTATUS code.
        /// </returns>
        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        internal static extern uint LsaOpenPolicy(
           ref LSA_UNICODE_STRING SystemName,
           ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
           uint DesiredAccess,
           out IntPtr PolicyHandle
        );

        /// <summary>
        /// The LsaClose function closes a handle to a Policy or TrustedDomain object.
        /// </summary>
        /// <param name="ObjectHandle"></param>
        /// <returns>
        ///     A handle to a Policy object returned by the LsaOpenPolicy function or to a 
        ///     TrustedDomain object returned by the LsaOpenTrustedDomainByName function. 
        ///     Following the completion of this call, the handle is no longer valid.
        /// </returns>
        [DllImport("advapi32.dll")]
        internal static extern long LsaClose(IntPtr ObjectHandle);

        /// <summary>
        /// The LsaNtStatusToWinError function converts an NTSTATUS code returned by an LSA function to a Windows error code.
        /// </summary>
        /// <param name="status">An NTSTATUS code returned by an LSA function call. </param>
        /// <returns>
        ///     The return value is the Windows error code that corresponds to the Status parameter. 
        ///     If there is no corresponding Windows error code, the return value is ERROR_MR_MID_NOT_FOUND.
        /// </returns>
        [DllImport("advapi32.dll")]
        internal static extern UInt32 LsaNtStatusToWinError(UInt32 status);

        /// <summary>
        /// The LsaEnumerateAccountRights function enumerates the privileges assigned to an account.
        /// </summary>
        /// <param name="PolicyHandle">A handle to a Policy object. The handle must have the POLICY_LOOKUP_NAMES access right.</param>
        /// <param name="AccountSid">Pointer to the SID of the account for which to enumerate privileges.</param>
        /// <param name="UserRights">
        ///     Receives a pointer to an array of LSA_UNICODE_STRING structures. 
        ///     Each structure contains the name of a privilege held by the account.
        /// </param>
        /// <param name="CountOfRights">Pointer to a variable that receives the number of privileges in the UserRights array.</param>
        /// <returns>
        ///     If at least one account right is found, the function succeeds and returns STATUS_SUCCESS.
        ///     If no account rights are found or if the function fails for any other reason, 
        ///     the function returns an NTSTATUS code such as FILE_NOT_FOUND.
        /// </returns>
        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern uint LsaEnumerateAccountRights(
            IntPtr PolicyHandle,
            [MarshalAs(UnmanagedType.LPArray)] byte[] AccountSid,
            out IntPtr UserRights,
            out uint CountOfRights
            );

        /// <summary>
        /// The LookupAccountName function accepts the name of a system and an account as input. 
        /// It retrieves a security identifier (SID) for the account and the name of the domain on which the account was found.
        /// The LsaLookupNames function can also retrieve computer accounts.
        /// </summary>
        /// <param name="lpSystemName">
        ///     A pointer to a null-terminated character string that specifies the name of the system. 
        ///     This string can be the name of a remote computer. If this string is NULL, 
        ///     the account name translation begins on the local system. 
        ///     If the name cannot be resolved on the local system, this function will try 
        ///     to resolve the name using domain controllers trusted by the local system. 
        ///     Generally, specify a value for lpSystemName only when the account is 
        ///     in an untrusted domain and the name of a computer in that domain is known.
        /// </param>
        /// <param name="lpAccountName">
        ///     A pointer to a null-terminated string that specifies the account name.
        ///     Use a fully qualified string in the domain_name\user_name format to 
        ///     ensure that LookupAccountName finds the account in the desired domain.
        /// </param>
        /// <param name="Sid">
        ///     A pointer to a buffer that receives the SID structure that corresponds 
        ///     to the account name pointed to by the lpAccountName parameter. 
        ///     If this parameter is NULL, cbSid must be zero.
        /// </param>
        /// <param name="cbSid">
        ///     A pointer to a variable. On input, this value specifies the size, in bytes, 
        ///     of the Sid buffer. If the function fails because the buffer is too small 
        ///     or if cbSid is zero, this variable receives the required buffer size.
        /// </param>
        /// <param name="ReferencedDomainName">
        ///     A pointer to a buffer that receives the name of the domain where the 
        ///     account name is found. For computers that are not joined to a domain, 
        ///     this buffer receives the computer name. If this parameter is NULL, 
        ///     the function returns the required buffer size.
        /// </param>
        /// <param name="cchReferencedDomainName">
        ///     A pointer to a variable. On input, this value specifies the size, 
        ///     in TCHARs, of the ReferencedDomainName buffer. If the function fails 
        ///     because the buffer is too small, this variable receives the required 
        ///     buffer size, including the terminating null character. 
        ///     If the ReferencedDomainName parameter is NULL, this parameter must be zero.
        /// </param>
        /// <param name="peUse"></param>
        /// <returns>
        ///     A pointer to a SID_NAME_USE enumerated type that indicates the type of 
        ///     the account when the function returns.
        /// </returns>
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern bool LookupAccountName(
            string lpSystemName,
            string lpAccountName,
            [MarshalAs(UnmanagedType.LPArray)] byte[] Sid,
            ref uint cbSid,
            StringBuilder ReferencedDomainName,
            ref uint cchReferencedDomainName,
            out SID_NAME_USE peUse);

        /// <summary>
        /// The LsaFreeMemory function frees memory allocated for an output buffer by an LSA function call. 
        /// LSA functions that return variable-length output buffers always allocate the buffer 
        /// on behalf of the caller. The caller must free this memory by passing the returned buffer 
        /// pointer to LsaFreeMemory when the memory is no longer required.
        /// </summary>
        /// <param name="Buffer">
        ///     Pointer to memory buffer that was allocated by an LSA function call. 
        ///     If LsaFreeMemory is successful, this buffer is freed.
        /// </param>
        /// <returns>
        ///     If the function succeeds, the return value is STATUS_SUCCESS.
        ///     If the function fails, the return value is an NTSTATUS code, which can be
        ///     STATUS_UNSUCCESSFUL
        /// </returns>
        [DllImport("advapi32")]
        internal static extern int LsaFreeMemory(IntPtr Buffer);


    }
}
