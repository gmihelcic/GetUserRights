using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Globalization;
using System.Linq;

namespace Microsoft.Pfe.GetUserRights
{
    public static class Utils
    {
        /// <summary>
        /// Local Group Membership Cache
        /// </summary>
        private static Dictionary<string, HashSet<string>> _usersInLocalGroups = null;

        /// <summary>
        /// Returns all, Domain and Local Groups where user is member directly or through Group nesting
        /// </summary>
        /// <param name="userName">Evaluated user's username in the form Domain\username</param>
        /// <returns></returns>
        public static IEnumerable<string> GetUserMembership(string userName)
        {
            if (string.IsNullOrWhiteSpace(userName))
                throw new ArgumentNullException(Properties.Resources.ResourceManager.GetString("strUserName", CultureInfo.CurrentCulture),
                    Properties.Resources.ResourceManager.GetString("strUserNameNull", CultureInfo.CurrentCulture));

            int i = 0; // Counter for feedback

            // Replace . with computerName or add ComputerName if provided only username
            userName = UpdateUserName(userName);

            // Split username to domain and username
            string[] userParts = userName.Split(new string[] { @"\" }, StringSplitOptions.RemoveEmptyEntries);

            UserPrincipal user = null;
            bool isOK = true;

            try
            {
                ContextType cType = ContextType.Domain;

                // Determine context type - Computer or Domain
                cType = (userParts[0].ToUpperInvariant() == Environment.MachineName.ToUpperInvariant()) ?
                    ContextType.Machine : ContextType.Domain;

                // Get Context
                using (PrincipalContext domainContext = new PrincipalContext(cType, userParts[0]))

                    // Find User account within context
                    user = UserPrincipal.FindByIdentity(domainContext, userParts[1]);
            }
            catch (PrincipalServerDownException)
            {
                isOK = false;
            }

            // Continue if we got user account
            if (user != null && isOK)
            {
                // Get all Security Groups user belongs
                PrincipalSearchResult<Principal> results = user.GetAuthorizationGroups();
                foreach (Principal result in results)
                {
                    i++;
                    //Console.Write("\rDomain Groups Evaluated: {0}", i);

                    // Get Local Groups where found group belongs
                    foreach (string group in GetLocalMembership(result))
                        yield return group;

                    // Return found group
                    yield return String.Format(CultureInfo.CurrentCulture, "{0}\\{1}", result.Context.Name, result.SamAccountName);
                }

                //Console.WriteLine();
                i = 0;

                // Enumerate all Local Groups where user belongs
                foreach (string group in GetLocalMembership(user))
                {
                    i++;
                    //Console.Write("\rLocal Groups Evaluated: {0}", i);
                    yield return group;
                }

                //Console.WriteLine();
            }
        }

        /// <summary>
        /// Get prncipal's Local Group Membership
        /// </summary>
        /// <param name="principal">Evaluated security principal in the form Domain\accountname</param>
        /// <returns>List of Local Groups where principal is member</returns>
        public static IEnumerable<string> GetLocalMembership(Principal principal)
        {
            if (principal == null)
                throw new ArgumentNullException(Properties.Resources.ResourceManager.GetString("strPrncipal", CultureInfo.CurrentCulture),
                    Properties.Resources.ResourceManager.GetString("strPrncipalNull", CultureInfo.CurrentCulture));

            // If Local Group Membership Dictionary isn't populated do populate it
            if (_usersInLocalGroups == null)
                PopulateLocalGroups();

            // We will search everything in lowercase
            string nbPrincipal = String.Format(CultureInfo.CurrentCulture, "{0}\\{1}", principal.Context.Name, principal.SamAccountName).ToUpperInvariant();

            // If principal has Local Group Membership list its membership
            if (_usersInLocalGroups.ContainsKey(nbPrincipal))
                foreach (string grp in _usersInLocalGroups[nbPrincipal])
                    yield return grp;
        }

        /// <summary>
        /// Populate local Group membership cache
        /// </summary>
        private static void PopulateLocalGroups()
        {
            // Initialize Cache
            _usersInLocalGroups = new Dictionary<string, HashSet<string>>();

            // Use WinNT provider to access Local Computer Identity data
            string path = String.Format(CultureInfo.CurrentCulture, "WinNT://{0},computer", System.Environment.MachineName);
            using (var computerEntry = new DirectoryEntry(path))
            {
                var localGroups = from DirectoryEntry childEntry in computerEntry.Children
                                  where childEntry.SchemaClassName == "Group"
                                  select childEntry;
                foreach (DirectoryEntry group in localGroups)
                {
                    foreach (object member in (System.Collections.IEnumerable)(group.Invoke("Members")))
                    {
                        using (DirectoryEntry obGpEntry = new DirectoryEntry(member))
                        {
                            string user = string.Format(CultureInfo.CurrentCulture, "{0}\\{1}", obGpEntry.Parent.Name, obGpEntry.Name).ToUpperInvariant();
                            if (!_usersInLocalGroups.ContainsKey(user))
                                _usersInLocalGroups.Add(user, new HashSet<string>());
                            _usersInLocalGroups[user].Add(group.Name);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Replace . with computerName or add ComputerName if provided only username
        /// </summary>
        /// <param name="userName">User name in format "username", ".\username" or "Authority\username"</param>
        /// <returns>Formated username</returns>
        internal static string UpdateUserName(string userName)
        {
            string[] userParts;

            if (userName.Contains(@"\"))
            {
                // Split username to domain and username
                userParts = userName.Split(new string[] { @"\" }, StringSplitOptions.RemoveEmptyEntries);
                // replace '.' with local machine name
                if (userParts[0] == ".") userParts[0] = System.Environment.MachineName;

            }
            else userParts = new string[] { System.Environment.MachineName, userName };

            return String.Format(CultureInfo.CurrentCulture, "{0}\\{1}", userParts);
        }
    }
}
