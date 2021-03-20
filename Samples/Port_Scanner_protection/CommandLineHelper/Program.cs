using System;
using System.Linq;
using System.Net;

namespace CommandLineHelper
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0 || args.Any(a => a == "/?"))
            {
                ShowHelp();
                return;
            }

            var block = args.Any(a => string.Equals(a, "-B", StringComparison.OrdinalIgnoreCase) || string.Equals(a, "-Block", StringComparison.OrdinalIgnoreCase));

            IPAddress address = null;
            ushort port = 0;
            for (int i = 0; i < args.Length; i++)
            {
                if (address is null)
                    IPAddress.TryParse(args[i], out address);

                if (port == 0)
                    ushort.TryParse(args[i], out port);

                if (!(address is null) && port > 0)
                    break;
            }

            if (address is null && port == 0)
            {
                ShowHelp();
                return;
            }

            if (address is null && port > 0)
            {
                if (block)
                {
                    FireWallHelper.ClosePort(port);
                }
                else
                {
                    Console.WriteLine("To close a port you need to add a remote IP address");
                    ShowHelp();
                }
            }
            else if (!(address is null))
            { 
                 if (block)
                {
                    FireWallHelper.CloseIP(address);
                }
                else
                {
                    FireWallHelper.OpenIP(address);
                }
            }

        }

        private static void ShowHelp()
        {
            Console.WriteLine("add -B to block");
            Console.WriteLine("Add IP address");
            Console.WriteLine("Add port number between 1 and 65535");
            Console.WriteLine("sample block google on port 80");
            Console.WriteLine("-B 8.8.8.4 80");
            Console.WriteLine("sample allow google on port 80");
            Console.WriteLine("8.8.8.4 80");
            Console.WriteLine("Press any key to exit");
            Console.ReadKey();
        }
    }
}
