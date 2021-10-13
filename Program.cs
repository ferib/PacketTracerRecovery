using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace BadTime
{
    class Program
    {

        #region ImportDLL
        //pinvoke windows DLL's for memory functions
        [DllImport("Kernel32.dll")]
        public static extern bool ReadProcessMemory(IntPtr handle, long address, byte[] bytes, long nsize, ref long op);

        [DllImport("Kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hwind, long Address, byte[] bytes, long nsize, out long output);

        [DllImport("Kernel32.dll")]
        public static extern IntPtr OpenProcess(int Token, bool inheritH, int ProcID);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, long lpAddress,
        uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32")]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int VirtualQuery(IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll")]
        public static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        public struct MEMORY_BASIC_INFORMATION
        {
            public long BaseAddress;
            public long AllocationBase;
            public long AllocationProtect;
            public long RegionSize;   // size of the region allocated by the program
            public long State;   // check if allocated (MEM_COMMIT)
            public long Protect; // page protection (must be PAGE_READWRITE)
            public long lType;
        }
        public struct SYSTEM_INFO
        {
            public ushort processorArchitecture;
            ushort reserved;
            public uint pageSize;
            public IntPtr minimumApplicationAddress;  // minimum address
            public IntPtr maximumApplicationAddress;  // maximum address
            public IntPtr activeProcessorMask;
            public uint numberOfProcessors;
            public uint processorType;
            public uint allocationGranularity;
            public ushort processorLevel;
            public ushort processorRevision;
        }
        enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        enum MemoryProtection
        {
            NoAccess = 0x0001,
            ReadOnly = 0x0002,
            ReadWrite = 0x0004,
            WriteCopy = 0x0008,
            Execute = 0x0010,
            ExecuteRead = 0x0020,
            ExecuteReadWrite = 0x0040,
            ExecuteWriteCopy = 0x0080,
            GuardModifierflag = 0x0100,
            NoCacheModifierflag = 0x0200,
            WriteCombineModifierflag = 0x0400,
            Proc_All_Access = 2035711
        }
        #endregion ImportDLL

        private static byte[] OriginalCode = { 0x41, 0x90, 0x01, 0x00, 0x00, 0x00, 0x44, 0x89, 0x90, 0x24, 0x90, 0x41, 0x83, 0x90, 0xFF, 0x4C, 0x90, 0xC7, 0x8B, 0xD3 };

        //41 ?? 01 00 00 00 44 89 ?? 24 ?? 41 83 ?? FF 4C ?? C7 8B D3
        private static long PatchOffsetLocation = 0x00;

        static void Main(string[] args)
        {
            Console.Title = "PacketTracer7 - Password Recovery Tool";
            PrintBanner();

            Process[] processes = Process.GetProcessesByName("PacketTracer7");
            if(processes.Count() == 0)
            {
                Console.WriteLine("Packet tracer not found!\nPlease open Packet Tracer first and try again.\n\nPress any key to exit...");
                Console.ReadKey();
                return;
            }
            Console.WriteLine("Packet tracer found!");
            foreach(var p in processes)
            {
                Console.WriteLine("Targeting PID 0x" + p.Id.ToString("X"));
                InjectAssembly(p);
            }
            Console.WriteLine("Done! Press any key to exit...");
            Console.ReadKey();
        }

        private static void PrintBanner()
        {
            Console.WriteLine("");
            Console.WriteLine(@"   __________                __           __    ___________                                   ");
            Console.WriteLine(@"   \______   \_____    ____ |  | __ _____/  |_  \__    ___/___________    ____  ___________   "); //ASCII art :-)
            Console.WriteLine(@"    |     ___/\__  \ _/ ___\|  |/ // __ \   __\   |    |  \_  __ \__  \ _/ ___\/ __ \_  __ \  ");
            Console.WriteLine(@"    |    |     / __ \\  \___|    <\  ___/|  |     |    |   |  | \// __ \\  \__\  ___/|  | \/  ");
            Console.WriteLine(@"    |____|    (____  /\___  >__|_ \\___  >__|     |____|   |__|  (____  /\___  >___  >__|     ");
            Console.WriteLine(@"                   \/     \/     \/    \/                             \/     \/    \/     (Recovery tool)");
            Console.Write("                                                                  BTC: ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("1Ferib");
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("RHR98Crux3DEZPXzjLBpfmHTHKqJ\n");
        }

        private static void InjectAssembly(Process process)
        {
            IntPtr wHandle = OpenProcess((int)MemoryProtection.Proc_All_Access, false, process.Id);
            long BytesWritten = 0;
            

            #region HookCave
            byte[] PWoverwrite = new byte[]
            {
                0xEB, 0x40,                                                                                       //jmp +64 bytes (Hash.length + jmpASM.length)
                0x38, 0x00, 0x30, 0x00, 0x35, 0x00, 0x46, 0x00, 0x34, 0x00, 0x30, 0x00, 0x31, 0x00, 0x31, 0x00, 0x37, 0x00, 0x32, 0x00, 0x37, 0x00, 0x45, 0x00, 0x37, 0x00, 0x46, 0x00, 0x41, 0x00, 0x33, 0x00, 0x46, 0x00, 0x43, 0x00, 0x35, 0x00, 0x44, 0x00, 0x37, 0x00, 0x46, 0x00, 0x46, 0x00, 0x45, 0x00, 0x45, 0x00, 0x32, 0x00, 0x42, 0x00, 0x42, 0x00, 0x42, 0x00, 0x35, 0x00, 0x45, 0x00, 0x43, 0x00, //Hash for PW: "Ferib"
                0x48, 0xB8, 0xDE, 0xAD, 0xC0, 0xDE, 0xDE, 0xC0, 0xAD, 0xDE,                                        //mov rcx, Alloc+2 (+67)
                0x50,   //push rax
                0x52,   //push rdx
                0x48, 0x8B, 0x10,
                0x48, 0x89, 0x11,
                0x48, 0x8B, 0x50, 0x08, //Some MOV's... cba putting time into it, 
                0x48, 0x89, 0x51, 0x08, //it's stable and it works, moste of you can't read it anyways
                0x48, 0x8B, 0x50, 0x10,
                0x48, 0x89, 0x51, 0x10,
                0x48, 0x8B, 0x50, 0x18,
                0x48, 0x89, 0x51, 0x18,
                0x48, 0x8B, 0x50, 0x20,
                0x48, 0x89, 0x51, 0x20,
                0x48, 0x8B, 0x50, 0x28,
                0x48, 0x89, 0x51, 0x28,
                0x48, 0x8B, 0x50, 0x30,
                0x48, 0x89, 0x51, 0x30,
                0x48, 0x8B, 0x50, 0x38,
                0x48, 0x89, 0x51, 0x38,
                0x5A,   //pop rdx
                0x58    //pop rax
            };
            #endregion

            //Patch at Base+0x148046C
            //AoB: 0x41, 0xBC, 0x01, 0x00, 0x00, 0x00, 0x44, 0x89, 0x64, 0x24, 0x20, 0x41, 0x83, 0xC9, 0xFF

            PatchOffsetLocation = AOBScan(wHandle, ref OriginalCode);
            //NOP everything after 15 bytes
            for(int i = 14; i < OriginalCode.Length; i++)
            {
                OriginalCode[i] = 0x90;
            }
           


            //PatchOffsetLocation = AOBScan(wHandle, DetourPattern) +3;
            if (PatchOffsetLocation > 0x0100)
            {
#if DEBUG
                Console.WriteLine("Placing hook at 0x" + PatchOffsetLocation.ToString("X"));
#endif
                //Console.WriteLine("Hooking data..");
            }
            else
            {
                Console.WriteLine("Failed finding location, already patched?");
                return;
            }

            long hAlloc = (long)VirtualAllocEx(wHandle, 0, (uint)PWoverwrite.Length + (uint)OriginalCode.Length + 15, AllocationType.Commit, MemoryProtection.ExecuteReadWrite);
            
            //Write Main Cave
            byte[] HashLocation = BitConverter.GetBytes(hAlloc + 2);
            for (int i = 0; i < 8; i++)
            {
                PWoverwrite[i + 68] = HashLocation[i];
            }
            WriteProcessMemory(wHandle, hAlloc, PWoverwrite, PWoverwrite.Length, out BytesWritten);
            if(BytesWritten == 0)
            {
                Console.WriteLine("Failed patching PacketTracer memory ;_;");
                return;
            }
            //Write Original Code
            WriteProcessMemory(wHandle, hAlloc + PWoverwrite.Length, OriginalCode, OriginalCode.Length, out BytesWritten);
            if (BytesWritten == 0)
            {
                Console.WriteLine("Failed patching PacketTracer memory ;_;");
                return;
            }

            //Write LongJumpBack
            byte[] LongJump = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xC0, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE,0x90 }; // + QWORD
            byte[] ReturnAddress = BitConverter.GetBytes(PatchOffsetLocation + 14);
            for(int i = 0; i < 8; i++)
            {
                LongJump[i + 6] = ReturnAddress[ i];
            }
            WriteProcessMemory(wHandle, hAlloc + PWoverwrite.Length + OriginalCode.Length, LongJump, LongJump.Length, out BytesWritten);
            if (BytesWritten == 0)
            {
                Console.WriteLine("Failed patching PacketTracer memory ;_;");
                return;
            }

            //Write Hook LongJump
            byte[] LongJump2 = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xC0, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE,0x90 }; // + QWORD
            byte[] ReturnAddress2 = BitConverter.GetBytes(hAlloc);
            for (int i = 0; i < 8; i++)
            {
                LongJump[i + 6] = ReturnAddress2[ i];
            }
            WriteProcessMemory(wHandle, PatchOffsetLocation, LongJump, LongJump.Length, out BytesWritten);
            if (BytesWritten == 0)
            {
                Console.WriteLine("Failed patching PacketTracer memory ;_;");
                return;
            }

            Console.WriteLine("Password set to \"Ferib\"");
        }

        //AoB scan function is used to locate original code, this supports multiple PacketTracer version (compared to using a offset)
        private static long AOBScan(IntPtr rHandle, ref byte[] AoBpattern)
        {
            long result = 0;
            // getting minimum & maximum address

            SYSTEM_INFO sys_info = new SYSTEM_INFO();
            GetSystemInfo(out sys_info);

            IntPtr proc_min_address = sys_info.minimumApplicationAddress;
            IntPtr proc_max_address = sys_info.maximumApplicationAddress;

            // saving the values as long ints so I won't have to do a lot of casts later
            ulong proc_min_address_l = (ulong)proc_min_address;
            ulong proc_max_address_l = (ulong)proc_max_address;

            // this will store any information we get from VirtualQueryEx()
            MEMORY_BASIC_INFORMATION mem_basic_info = new MEMORY_BASIC_INFORMATION();

            long bytesRead = 0;  // number of bytes read with ReadProcessMemory
            while (proc_min_address_l < proc_max_address_l)
            {
                // 28 = sizeof(MEMORY_BASIC_INFORMATION)
                VirtualQueryEx(rHandle, proc_min_address, out mem_basic_info, 56);
                //Console.WriteLine((mem_basic_info.BaseAddress).ToString("X"));
#if DEBUG
                Console.Write("0x" + proc_min_address.ToString("X"));
#endif
                // if this memory chunk is accessible
                if (mem_basic_info.AllocationProtect <= 0x80 && mem_basic_info.AllocationProtect >= 0x20 && mem_basic_info.RegionSize < int.MaxValue)
                {
#if DEBUG
                    Console.Write(" scanning..");
#endif
                    byte[] ScanMemory = new byte[mem_basic_info.RegionSize];
                    byte[] buffer = new byte[mem_basic_info.RegionSize];

                    // read everything in the buffer above
                    ReadProcessMemory(rHandle, mem_basic_info.BaseAddress, buffer, mem_basic_info.RegionSize, ref bytesRead);

                    for (long i = 0; i < buffer.Length - AoBpattern.Length - 1; i++)
                    {
                        for (long j = 0; j < AoBpattern.Length; j++)
                        {
                            if (j == AoBpattern.Length - 1)
                            {
                                //restore pattern from wildmarks
                                for (long x = AoBpattern.Length-1; x >= 0; x--)
                                {
                                    AoBpattern[x] = buffer[i + j - AoBpattern.Length + 1 + x];
                                }
                                return result = (long)proc_min_address + i;
                            }
                            if(AoBpattern[j] != 0x90)//NOP (0x90) was used as wildcard, restore it
                            {
                                if (buffer[i + j] != AoBpattern[j])
                                    break;
                            }
                        }
                    }
                }
#if DEBUG
                Console.WriteLine("");
#endif

                // move to the next memory chunk
                proc_min_address_l += (ulong)mem_basic_info.RegionSize;
                proc_min_address = (IntPtr)proc_min_address_l;
            }
            //Console.WriteLine("Pathcing at: 0x" + result.ToString("X"));

            return result;
        }
    }
}
