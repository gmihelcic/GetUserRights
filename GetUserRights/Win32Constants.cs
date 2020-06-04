namespace Microsoft.Pfe.GetUserRights
{
    public static class Win32Constants
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores", Justification = "<Pending>")]
        public const int ERROR_SUCCESS = 0;                 // The operation completed successfully.
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores", Justification = "<Pending>")]
        public const int ERROR_INSUFFICIENT_BUFFER = 122;   // The data area passed to a system call is too small.
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores", Justification = "<Pending>")]
        public const int ERROR_INVALID_FLAGS = 1004;        // Invalid flags.
    }
}
