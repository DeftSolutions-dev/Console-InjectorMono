using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace InjectorMono
{
    class Program
    {
        static void Main(string[] args)
        {
            if (Process.GetProcessesByName("Stay Alive").Length != 0)
            {
                IntPtr remoteAssembly = IntPtr.Zero;
                Process process = Process.GetProcesses().FirstOrDefault(p => p.ProcessName.Equals("Stay Alive", StringComparison.OrdinalIgnoreCase));
                DLL dll = new DLL();
                handle = OpenProcess(ProcessAccessFlags.All | ProcessAccessFlags.VirtualMemoryRead | ProcessAccessFlags.VirtualMemoryWrite | ProcessAccessFlags.VirtualMemoryOperation, false, process.Id);
                GetMonoModule(handle, out mono);
                new Program().Inject(DLL.dll, "A", "B", "C");
                return;
            }
            Console.WriteLine("Open Stay Alive BRO...");
            Console.ReadKey();
        }
        #region DllImport
        [DllImport("psapi.dll", SetLastError = true)]
        public static extern bool EnumProcessModulesEx(IntPtr hProcess, [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)][In][Out] IntPtr[] lphModule, int cb, [MarshalAs(UnmanagedType.U4)] out int lpcbNeeded, uint dwFilterFlag);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);
        [DllImport("psapi.dll")]
        public static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName, [In][MarshalAs(UnmanagedType.U4)] uint nSize);
        [DllImport("psapi.dll", SetLastError = true)]
        public static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule, out MODULEINFO lpmodinfo, uint cb);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(IntPtr hHandle, int dwMilliseconds);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, int dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out int lpThreadId);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, int lpNumberOfBytesRead = 0);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint dwFreeType);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, int lpNumberOfBytesWritten = 0);
        #endregion
        #region ....
        public static string ReadString(IntPtr address, int length, Encoding encoding)
        {
            List<byte> bytes = new List<byte>();
            for (int i = 0; i < length; i++)
            {
                byte read = ReadBytes(address + bytes.Count, 1)[0];
                if (read == 0x00)
                    break;
                bytes.Add(read);
            }
            return encoding.GetString(bytes.ToArray());
        }
        public static short ReadShort(IntPtr address)
        {
            return BitConverter.ToInt16(ReadBytes(address, 2), 0);
        }
        public static int ReadInt(IntPtr address)
        {
            return BitConverter.ToInt32(ReadBytes(address, 4), 0);
        }
        public static byte[] ReadBytes(IntPtr address, int size)
        {
            byte[] bytes = new byte[size];
            ReadProcessMemory(handle, address, bytes, size);
            return bytes;
        }
        public IntPtr AllocateAndWrite(byte[] data)
        {
            IntPtr addr = Allocate(data.Length);
            Write(addr, data);
            return addr;
        }
        public IntPtr AllocateAndWrite(string data) => AllocateAndWrite(Encoding.UTF8.GetBytes(data));
        public IntPtr AllocateAndWrite(int data) => AllocateAndWrite(BitConverter.GetBytes(data));
        public IntPtr Allocate(int size)
        {
            IntPtr addr = VirtualAllocEx(handle, IntPtr.Zero, size, MEM_COMMIT, 0x40);
            all.Add(addr, size);
            return addr;
        }
        public void Write(IntPtr addr, byte[] data)
        {
            WriteProcessMemory(handle, addr, data, data.Length);
        }
        #endregion
        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        } 
        private const uint MEM_COMMIT = 0x00001000;
        private const uint MEM_DECOMMIT = 0x4000;
        private static Dictionary<string, IntPtr> Exports = new Dictionary<string, IntPtr>
        {
            { "mono_get_root_domain", IntPtr.Zero }, { "mono_thread_attach", IntPtr.Zero },
            { "mono_image_open_from_data", IntPtr.Zero }, { "mono_assembly_load_from_full", IntPtr.Zero },
            { "mono_assembly_get_image", IntPtr.Zero }, { "mono_class_from_name", IntPtr.Zero },
            { "mono_class_get_method_from_name", IntPtr.Zero }, { "mono_runtime_invoke", IntPtr.Zero },
        };
        private static IntPtr Domain;
        private static bool attach;
        private static IntPtr handle;
        private static IntPtr mono;
        private static Dictionary<IntPtr, int> all = new Dictionary<IntPtr, int>();
        // Win32Api структуры подписей.
        #region Win32ApiStruct
        public struct MODULEINFO
        {
            public IntPtr lpBaseOfDll;
            public int SizeOfImage;
            public IntPtr EntryPoint;
        }

        public struct ExportedFunction
        {
            public string Name;
            public IntPtr Address;
            public ExportedFunction(string name, IntPtr address)
            {
                Name = name;
                Address = address;
            }
        }
        #endregion
        public void Inject(byte[] rawAssembly, string @namespace, string className, string methodName)
        {
            foreach (ExportedFunction ef in GetExportedFunctions(handle, mono))
            {
                if (Exports.ContainsKey(ef.Name))
                {
                    Exports[ef.Name] = ef.Address;
                }
            }
            Domain = Execute(Exports["mono_get_root_domain"]);
            IntPtr statusPtr = Allocate(4);
            IntPtr rawImg = Execute(Exports["mono_image_open_from_data"], AllocateAndWrite(rawAssembly), (IntPtr)rawAssembly.Length, (IntPtr)1, statusPtr);
            attach = true;
            IntPtr inassembly = Execute(Exports["mono_assembly_load_from_full"], rawImg, AllocateAndWrite(new byte[1]), statusPtr, IntPtr.Zero);
            IntPtr assemblyimage = Execute(Exports["mono_assembly_get_image"], inassembly);
            IntPtr classfromname = Execute(Exports["mono_class_from_name"], assemblyimage, AllocateAndWrite(@namespace), AllocateAndWrite(className));
            IntPtr methodfromname = Execute(Exports["mono_class_get_method_from_name"], classfromname, AllocateAndWrite(methodName), IntPtr.Zero);
            IntPtr excPtr = AllocateAndWrite(0);
            Execute(Exports["mono_runtime_invoke"], methodfromname, IntPtr.Zero, IntPtr.Zero, excPtr);
        }
        private IntPtr Execute(IntPtr address, params IntPtr[] args)
        {
            IntPtr retValPtr = AllocateAndWrite(0);
            byte[] code = Asm(address, retValPtr, args);
            IntPtr alloc = AllocateAndWrite(code);
            IntPtr thread = CreateRemoteThread(handle, IntPtr.Zero, 0, alloc, IntPtr.Zero, 0, out _);
            WaitForSingleObject(thread, -1);
            IntPtr ret = (IntPtr)ReadInt(retValPtr);
            return ret;
        }
        private byte[] Asm(IntPtr functionPtr, IntPtr retValPtr, IntPtr[] args)
        {
            List<byte> asm = new List<byte>();
            if (attach)
            {
                if ((int)Domain < 128)
                {
                    asm.Add(0x6A);
                }
                else { asm.Add(0x68); }
                if ((int)Domain <= 255)
                {
                    asm.AddRange(new[] { (byte)Domain });
                }
                else { asm.AddRange(BitConverter.GetBytes((int)Domain)); }
                asm.Add(0xB8);
                asm.AddRange(BitConverter.GetBytes((int)Exports["mono_thread_attach"]));
                asm.AddRange(new byte[] { 0xFF, 0xD0 }); asm.AddRange(new byte[] { 0x83, 0xC4 });
                asm.Add(4);
            }
            for (int i = args.Length - 1; i >= 0; i--)
            {
                asm.Add((int)args[i] < 128 ? (byte)0x6A : (byte)0x68);
                asm.AddRange((int)args[i] <= 255 ? new[] { (byte)args[i] } : BitConverter.GetBytes((int)args[i]));
            }
            asm.Add(0xB8); asm.AddRange(BitConverter.GetBytes((int)functionPtr));
            asm.AddRange(new byte[] { 0xFF, 0xD0 }); asm.AddRange(new byte[] { 0x83, 0xC4 });
            asm.Add((byte)(args.Length * 4)); asm.Add(0xA3); asm.AddRange(BitConverter.GetBytes((int)retValPtr));
            asm.Add(0xC3);
            return asm.ToArray();
        }
        public static bool GetMonoModule(IntPtr handle, out IntPtr monoModule)
        {
            IntPtr[] ptrs = new IntPtr[0];
            EnumProcessModulesEx(handle, ptrs, 0, out int bytesNeeded, 0x03);
            int count = bytesNeeded / 4;
            ptrs = new IntPtr[count];
            EnumProcessModulesEx(handle, ptrs, bytesNeeded, out bytesNeeded, 0x03);
            for (int i = 0; i < count; i++)
            {
                StringBuilder path = new StringBuilder(260);
                GetModuleFileNameEx(handle, ptrs[i], path, 260);
                if (path.ToString().IndexOf("mono", StringComparison.OrdinalIgnoreCase) > -1)
                {
                    GetModuleInformation(handle, ptrs[i], out MODULEINFO info, (uint)(4 * ptrs.Length));

                    var funcs = GetExportedFunctions(handle, info.lpBaseOfDll);

                    if (funcs.Any(f => f.Name == "mono_get_root_domain"))
                    {
                        monoModule = info.lpBaseOfDll;
                        return true;
                    }
                }
            }
            monoModule = IntPtr.Zero;
            return false;
        }
        public static IEnumerable<ExportedFunction> GetExportedFunctions(IntPtr handle, IntPtr mod)
        {
            // адрес загрузки модуля
            int e_lfanew = ReadInt(mod + 0x3C);
            IntPtr ntHeaders = mod + e_lfanew;
            IntPtr optionalHeader = ntHeaders + 0x18;
            IntPtr dataDirectory = optionalHeader + 0x60;
            IntPtr exportDirectory = mod + ReadInt(dataDirectory);
            IntPtr names = mod + ReadInt(exportDirectory + 0x20);
            IntPtr ordinals = mod + ReadInt(exportDirectory + 0x24);
            IntPtr functions = mod + ReadInt(exportDirectory + 0x1C);
            int count = ReadInt(exportDirectory + 0x18);
            for (int i = 0; i < count; i++)
            {
                int offset = ReadInt(names + i * 4);
                string name = ReadString(mod + offset, 32, Encoding.ASCII);
                short ordinal = ReadShort(ordinals + i * 2);
                IntPtr address = mod + ReadInt(functions + ordinal * 4);
                if (address != IntPtr.Zero)
                    yield return new ExportedFunction(name, address);
            }
            foreach (var kvp in all)
            {
                VirtualFreeEx(Program.handle, kvp.Key, kvp.Value, MEM_DECOMMIT);
            }
        }
    }
}
