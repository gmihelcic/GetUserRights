using System;
using System.Globalization;
using System.Linq;

namespace Microsoft.Pfe.GetUserRights
{
    class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            //Check Argument count
            if (args.Length > 1)
            {
                ShowUsage();
                return;
            }

            // Get Loged On user 
            string userName = System.Security.Principal.WindowsIdentity.GetCurrent().Name;

            // Get user provided on the command line (if provided)
            if (args.Length == 1)
            {
                userName = args[0];
                // Replace . with computerName or add ComputerName if provided only username
                userName = Utils.UpdateUserName(userName);
            }

            // Display target user
            Console.WriteLine(Properties.Resources.ResourceManager.GetString("strEffectiveRights", CultureInfo.CurrentCulture), userName);

            // Enumerate policies and print them on the screen
            foreach (string right in PolicyReader.GetAllRights(userName))
            {
                Console.WriteLine(right);
            }
        }

        /// <summary>
        /// Print Application Usage instructions
        /// </summary>
        static void ShowUsage()
        {
            Console.WriteLine(Properties.Resources.ResourceManager.GetString("strUsage", CultureInfo.CurrentCulture));
            Console.WriteLine(Properties.Resources.ResourceManager.GetString("strUsageCmd", CultureInfo.CurrentCulture));
            Console.WriteLine(Properties.Resources.ResourceManager.GetString("strUsageExplain", CultureInfo.CurrentCulture));
        }
    }
}
