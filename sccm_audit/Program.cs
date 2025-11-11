using System;
using Microsoft.Win32;

namespace sccm_audit
{
    class Program
    {
        private const string SCCM_BASE = @"SOFTWARE\Microsoft\SMS";

        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Usage: PSSRecon.exe <hostname>");
                Console.WriteLine("Example: PSSRecon.exe pss.corp.local");
                return;
            }

            string host = args[0];

            try
            {
                Console.WriteLine($"[*] Connecting to {host} as {Environment.UserDomainName}\\{Environment.UserName}");
                Enumerate(host);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error: {ex.Message}");
            }
        }

        static void Enumerate(string host)
        {
            try
            {
                using (RegistryKey remoteReg = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, host))
                {
                    EnumeratePSSRoles(remoteReg);
                    EnumerateSiteDB(remoteReg);
                }
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("[-] Access denied. Current user lacks permissions to access the remote registry.");
            }
            catch (System.IO.IOException ex)
            {
                Console.WriteLine($"[-] Network error: {ex.Message}");
                Console.WriteLine("[-] Ensure Remote Registry service is running on target");
            }
        }

        static void EnumeratePSSRoles(RegistryKey remoteReg)
        {
            try
            {
                using (RegistryKey smsKey = remoteReg.OpenSubKey(SCCM_BASE))
                {
                    if (smsKey == null)
                    {
                        Console.WriteLine("[-] SCCM installation not found");
                        return;
                    }

                    string[] subKeys = smsKey.GetSubKeyNames();

                    foreach (string subKey in subKeys)
                    {
                        if (subKey.Equals("DP", StringComparison.OrdinalIgnoreCase))
                        {
                            Console.WriteLine("[+] Distrubution Point Installed");
                            EnumerateDP(remoteReg);
                        }

                        if (subKey.Equals("MP", StringComparison.OrdinalIgnoreCase))
                        {
                            Console.WriteLine("[+] Management Point Installed");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error enumerating PSS roles: {ex.Message}");
            }
        }

        static void EnumerateDP(RegistryKey remoteReg)
        {
            try
            {
                string dpPath = $@"{SCCM_BASE}\DP";
                using (RegistryKey dpKey = remoteReg.OpenSubKey(dpPath))
                {
                    if (dpKey == null) return;

                    string siteCode = dpKey.GetValue("SiteCode") as string;
                    if (!string.IsNullOrEmpty(siteCode))
                        Console.WriteLine($"[+] Site Code Found: {siteCode}");

                    string siteServer = dpKey.GetValue("SiteServer") as string;
                    if (!string.IsNullOrEmpty(siteServer))
                        Console.WriteLine($"[+] Site Server Found: {siteServer}");

                    string managementPoints = dpKey.GetValue("ManagementPoints") as string;
                    if (!string.IsNullOrEmpty(managementPoints))
                    {
                        string[] mps = managementPoints.Split(new[] { '*' }, StringSplitOptions.RemoveEmptyEntries);
                        foreach (string mp in mps)
                        {
                            if (!string.IsNullOrWhiteSpace(mp))
                                Console.WriteLine($"[+] Management Point Found: {mp}");
                        }
                    }

                    object isAnon = dpKey.GetValue("IsAnonymousAccessEnabled");
                    if (isAnon != null && Convert.ToInt32(isAnon) == 1)
                        Console.WriteLine("[+] Anonymous Access On This Distrubution Point Is Enabled");

                    object isPXE = dpKey.GetValue("IsPXE");
                    if (isPXE != null && Convert.ToInt32(isPXE) == 1)
                        Console.WriteLine("[+] PXE Installed");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error enumerating DP: {ex.Message}");
            }
        }

        static void EnumerateSiteDB(RegistryKey remoteReg)
        {
            try
            {
                string dbPath = $@"{SCCM_BASE}\COMPONENTS\SMS_SITE_COMPONENT_MANAGER\Multisite Component Servers";
                using (RegistryKey dbKey = remoteReg.OpenSubKey(dbPath))
                {
                    if (dbKey == null)
                    {
                        Console.WriteLine("[+] Site Database is Local to the Primary Site Server");
                        return;
                    }

                    string[] subKeys = dbKey.GetSubKeyNames();

                    if (subKeys.Length == 1)
                        Console.WriteLine($"[+] Site Database Found: {subKeys[0]}");
                    else if (subKeys.Length == 0)
                        Console.WriteLine("[+] Site Database is Local to the Primary Site Server");
                    else
                    {
                        foreach (string server in subKeys)
                            Console.WriteLine($"[+] Multisite Component Server: {server}");
                    }
                }
            }
            catch (Exception)
            {
                Console.WriteLine("[+] Site Database is Local to the Primary Site Server");
            }
        }
    }
}