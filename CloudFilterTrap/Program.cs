//  This file is part of WindowsMemoryAccessTraps.
//  Copyright (C) Google LLC 2021
//
//  WindowsMemoryAccessTraps is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  WindowsMemoryAccessTraps is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with WindowsMemoryAccessTraps.  If not, see <http://www.gnu.org/licenses/>.

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace CloudFilterTrap;

static class Program
{
    /* All hail our AI overlords (generated with Gemini) */
    public static void HexDump(IntPtr address, int length)
    {
        if (address == IntPtr.Zero)
        {
            Console.WriteLine("Error: IntPtr is null.");
            return;
        }
        if (length <= 0)
        {
            Console.WriteLine("Error: Length must be greater than zero.");
            return;
        }

        // Determine the number of bytes per line for the hexdump display
        const int bytesPerLine = 16;

        // Create a managed byte array to hold the data copied from unmanaged memory
        byte[] buffer = new byte[length];

        try
        {
            // Copy data from the unmanaged memory address to the managed byte array
            // This is the correct way to read bytes from an IntPtr into a managed byte array. 【1】
            Marshal.Copy(address, buffer, 0, length);
        }
        catch (AccessViolationException ex)
        {
            Console.WriteLine($"Error: Could not access unmanaged memory. {ex.Message}");
            return;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"An unexpected error occurred during memory copy: {ex.Message}");
            return;
        }

        Console.WriteLine($"Hexdump of memory at 0x{address.ToInt64():X}:");
        Console.WriteLine("--------------------------------------------------------------------------------");

        // Iterate through the buffer, processing bytes in chunks of bytesPerLine
        for (int i = 0; i < length; i += bytesPerLine)
        {
            // Print the current offset in hexadecimal
            Console.Write($"0x{i:X8} | ");

            // Build the hexadecimal string for the current line
            StringBuilder hexLine = new StringBuilder();
            // Build the ASCII string for the current line
            StringBuilder asciiLine = new StringBuilder();

            for (int j = 0; j < bytesPerLine; j++)
            {
                if (i + j < length)
                {
                    byte b = buffer[i + j];
                    // Append the byte as a two-digit hexadecimal string
                    hexLine.Append($"{b:X2} ");

                    // Append the ASCII character, replacing non-printable characters with '.'
                    if (b >= 32 && b <= 126) // Printable ASCII range
                    {
                        asciiLine.Append((char)b);
                    }
                    else
                    {
                        asciiLine.Append('.');
                    }
                }
                else
                {
                    // Pad with spaces if we're at the end of the data and the line isn't full
                    hexLine.Append("   ");
                    asciiLine.Append(' ');
                }

                // Add an extra space in the hex section for better readability after 8 bytes
                if (j == 7)
                {
                    hexLine.Append(" ");
                }
            }

            // Print the formatted hexadecimal and ASCII lines
            Console.WriteLine($"{hexLine}| {asciiLine}");
        }
        Console.WriteLine("--------------------------------------------------------------------------------");
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct LargeIntegerStruct
    {
        [FieldOffset(0)]
        public uint LowPart;
        [FieldOffset(4)]
        public int HighPart;
        [FieldOffset(0)]
        public long QuadPart;

        public LargeIntegerStruct(long quadpart)
        {
            LowPart = 0;
            HighPart = 0;
            QuadPart = quadpart;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FileBasicInformation
    {
        public LargeIntegerStruct CreationTime;
        public LargeIntegerStruct LastAccessTime;
        public LargeIntegerStruct LastWriteTime;
        public LargeIntegerStruct ChangeTime;
        public FileAttributes FileAttributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct CF_FS_METADATA
    {
        public FileBasicInformation BasicInfo;
        public LargeIntegerStruct FileSize;
    }

    [Flags]
    enum CF_PLACEHOLDER_CREATE_FLAGS
    {
        CF_PLACEHOLDER_CREATE_FLAG_NONE = 0x00000000,
        CF_PLACEHOLDER_CREATE_FLAG_DISABLE_ON_DEMAND_POPULATION = 0x00000001,
        CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC = 0x00000002,
        CF_PLACEHOLDER_CREATE_FLAG_SUPERSEDE = 0x00000004,
        CF_PLACEHOLDER_CREATE_FLAG_ALWAYS_FULL = 0x00000008,
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct CF_PLACEHOLDER_CREATE_INFO
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string RelativeFileName;
        public CF_FS_METADATA FsMetadata;
        public IntPtr FileIdentity;
        public int FileIdentityLength;
        public CF_PLACEHOLDER_CREATE_FLAGS Flags;
        public int Result;
        public long CreateUsn;
    }

    [Flags]
    enum CF_SYNC_PROVIDER_STATUS : uint
    {
        CF_PROVIDER_STATUS_DISCONNECTED = 0x00000000,
        CF_PROVIDER_STATUS_IDLE = 0x00000001,
        CF_PROVIDER_STATUS_POPULATE_NAMESPACE = 0x00000002,
        CF_PROVIDER_STATUS_POPULATE_METADATA = 0x00000004,
        CF_PROVIDER_STATUS_POPULATE_CONTENT = 0x00000008,
        CF_PROVIDER_STATUS_SYNC_INCREMENTAL = 0x00000010,
        CF_PROVIDER_STATUS_SYNC_FULL = 0x00000020,
        CF_PROVIDER_STATUS_CONNECTIVITY_LOST = 0x00000040,

        CF_PROVIDER_STATUS_CLEAR_FLAGS = 0x80000000,
        CF_PROVIDER_STATUS_TERMINATED = 0xC0000001,
        CF_PROVIDER_STATUS_ERROR = 0xC0000002,
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct CF_PROCESS_INFO
    {
        public int StructSize;
        public int ProcessId;
        public string ImagePath;
        public string PackageName;
        public string ApplicationId;
        public string CommandLine;
        public int SessionId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct CF_PLATFORM_INFO
    {
        public int BuildNumber;
        public int RevisionNumber;
        public int IntegrationNumber;
    }

    [DllImport("cldapi.dll", CharSet = CharSet.Unicode, PreserveSig = false)]
    static extern void CfGetPlatformInfo(out CF_PLATFORM_INFO PlatformInfo);

    enum CF_HYDRATION_POLICY_PRIMARY : ushort
    {
        CF_HYDRATION_POLICY_PARTIAL = 0,
        CF_HYDRATION_POLICY_PROGRESSIVE = 1,
        CF_HYDRATION_POLICY_FULL = 2,
        CF_HYDRATION_POLICY_ALWAYS_FULL = 3,
    }

    [Flags]
    enum CF_HYDRATION_POLICY_MODIFIER : ushort
    {
        CF_HYDRATION_POLICY_MODIFIER_NONE = 0x0000,
        CF_HYDRATION_POLICY_MODIFIER_VALIDATION_REQUIRED = 0x0001,
        CF_HYDRATION_POLICY_MODIFIER_STREAMING_ALLOWED = 0x0002,
        CF_HYDRATION_POLICY_MODIFIER_AUTO_DEHYDRATION_ALLOWED = 0x0004,
    }

    [StructLayout(LayoutKind.Sequential)]
    struct CF_HYDRATION_POLICY
    {
        public CF_HYDRATION_POLICY_PRIMARY Primary;
        public CF_HYDRATION_POLICY_MODIFIER Modifier;
    }

    enum CF_POPULATION_POLICY_PRIMARY : ushort
    {
        CF_POPULATION_POLICY_PARTIAL = 0,
        CF_POPULATION_POLICY_FULL = 2,
        CF_POPULATION_POLICY_ALWAYS_FULL = 3,
    }

    enum CF_POPULATION_POLICY_MODIFIER : ushort
    {
        CF_POPULATION_POLICY_MODIFIER_NONE = 0x0000,
    }

    [StructLayout(LayoutKind.Sequential)]
    struct CF_POPULATION_POLICY
    {
        public CF_POPULATION_POLICY_PRIMARY Primary;
        public CF_POPULATION_POLICY_MODIFIER Modifier;
    }

    [Flags]
    enum CF_PLACEHOLDER_MANAGEMENT_POLICY
    {
        CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT = 0x00000000,
        CF_PLACEHOLDER_MANAGEMENT_POLICY_CREATE_UNRESTRICTED = 0x00000001,
        CF_PLACEHOLDER_MANAGEMENT_POLICY_CONVERT_TO_UNRESTRICTED = 0x00000002,
        CF_PLACEHOLDER_MANAGEMENT_POLICY_UPDATE_UNRESTRICTED = 0x00000004,
    }

    [Flags]
    enum CF_INSYNC_POLICY : uint
    {
        CF_INSYNC_POLICY_NONE = 0x00000000,
        CF_INSYNC_POLICY_TRACK_FILE_CREATION_TIME = 0x00000001,
        CF_INSYNC_POLICY_TRACK_FILE_READONLY_ATTRIBUTE = 0x00000002,
        CF_INSYNC_POLICY_TRACK_FILE_HIDDEN_ATTRIBUTE = 0x00000004,
        CF_INSYNC_POLICY_TRACK_FILE_SYSTEM_ATTRIBUTE = 0x00000008,
        CF_INSYNC_POLICY_TRACK_DIRECTORY_CREATION_TIME = 0x00000010,
        CF_INSYNC_POLICY_TRACK_DIRECTORY_READONLY_ATTRIBUTE = 0x00000020,
        CF_INSYNC_POLICY_TRACK_DIRECTORY_HIDDEN_ATTRIBUTE = 0x00000040,
        CF_INSYNC_POLICY_TRACK_DIRECTORY_SYSTEM_ATTRIBUTE = 0x00000080,
        CF_INSYNC_POLICY_TRACK_FILE_LAST_WRITE_TIME = 0x00000100,
        CF_INSYNC_POLICY_TRACK_DIRECTORY_LAST_WRITE_TIME = 0x00000200,
        CF_INSYNC_POLICY_TRACK_FILE_ALL = 0x0055550f,
        CF_INSYNC_POLICY_TRACK_DIRECTORY_ALL = 0x00aaaaf0,
        CF_INSYNC_POLICY_TRACK_ALL = 0x00ffffff,
        CF_INSYNC_POLICY_PRESERVE_INSYNC_FOR_SYNC_ENGINE = 0x80000000,
    }

    [Flags]
    enum CF_HARDLINK_POLICY
    {
        CF_HARDLINK_POLICY_NONE = 0x00000000,
        CF_HARDLINK_POLICY_ALLOWED = 0x00000001,
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct CF_SYNC_POLICIES
    {
        public int StructSize;
        public CF_HYDRATION_POLICY Hydration;
        public CF_POPULATION_POLICY Population;
        public CF_INSYNC_POLICY InSync;
        public CF_HARDLINK_POLICY HardLink;
        public CF_PLACEHOLDER_MANAGEMENT_POLICY PlaceholderManagement;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct CF_SYNC_REGISTRATION
    {
        public int StructSize;
        public string ProviderName;
        public string ProviderVersion;
        public IntPtr SyncRootIdentity;
        public int SyncRootIdentityLength;
        public IntPtr FileIdentity;
        public int FileIdentityLength;
        public Guid ProviderId;
    }

    [Flags]
    enum CF_REGISTER_FLAGS
    {
        CF_REGISTER_FLAG_NONE = 0x00000000,
        CF_REGISTER_FLAG_UPDATE = 0x00000001,
        CF_REGISTER_FLAG_DISABLE_ON_DEMAND_POPULATION_ON_ROOT = 0x00000002,
        CF_REGISTER_FLAG_MARK_IN_SYNC_ON_ROOT = 0x00000004,
    }

    [DllImport("cldapi.dll", CharSet = CharSet.Unicode)]
    static extern int CfRegisterSyncRoot(
        string SyncRootPath,
        in CF_SYNC_REGISTRATION Registration,
        in CF_SYNC_POLICIES Policies,
        CF_REGISTER_FLAGS RegisterFlags
    );

    [DllImport("cldapi.dll", CharSet = CharSet.Unicode)]
    static extern int CfUnregisterSyncRoot(
        string SyncRootPath
    );

    const byte CF_MAX_PRIORITY_HINT = 15;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct CF_CALLBACK_INFO
    {
        public int StructSize;
        public long ConnectionKey;
        public IntPtr CallbackContext;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string VolumeGuidName;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string VolumeDosName;
        public int VolumeSerialNumber;
        public LargeIntegerStruct SyncRootFileId;
        public IntPtr SyncRootIdentity;
        public int SyncRootIdentityLength;
        public LargeIntegerStruct FileId;
        public LargeIntegerStruct FileSize;
        public IntPtr FileIdentity;
        public int FileIdentityLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string NormalizedPath;
        public long TransferKey;
        public byte PriorityHint;
        public IntPtr CorrelationVector;                  // PCORRELATION_VECTOR 
        public IntPtr ProcessInfo;                        // CF_PROCESS_INFO*
        public long RequestKey;
    }

    [Flags]
    enum CF_CALLBACK_CANCEL_FLAGS
    {
        CF_CALLBACK_CANCEL_FLAG_NONE = 0x00000000,
        CF_CALLBACK_CANCEL_FLAG_IO_TIMEOUT = 0x00000001,
        CF_CALLBACK_CANCEL_FLAG_IO_ABORTED = 0x00000002,
    }

    [Flags]
    enum CF_CALLBACK_FETCH_DATA_FLAGS
    {
        CF_CALLBACK_FETCH_DATA_FLAG_NONE = 0x00000000,
        CF_CALLBACK_FETCH_DATA_FLAG_RECOVERY = 0x00000001,
        CF_CALLBACK_FETCH_DATA_FLAG_EXPLICIT_HYDRATION = 0x00000002,
    }

    [Flags]
    enum CF_CALLBACK_VALIDATE_DATA_FLAGS
    {
        CF_CALLBACK_VALIDATE_DATA_FLAG_NONE = 0x00000000,
        CF_CALLBACK_VALIDATE_DATA_FLAG_EXPLICIT_HYDRATION = 0x00000002,
    }

    [Flags]
    enum CF_CALLBACK_FETCH_PLACEHOLDERS_FLAGS
    {
        CF_CALLBACK_FETCH_PLACEHOLDERS_FLAG_NONE = 0x00000000,
    }

    [Flags]
    enum CF_CALLBACK_OPEN_COMPLETION_FLAGS
    {
        CF_CALLBACK_OPEN_COMPLETION_FLAG_NONE = 0x00000000,
        CF_CALLBACK_OPEN_COMPLETION_FLAG_PLACEHOLDER_UNKNOWN = 0x00000001,
        CF_CALLBACK_OPEN_COMPLETION_FLAG_PLACEHOLDER_UNSUPPORTED = 0x00000002,
    }

    [Flags]
    enum CF_CALLBACK_CLOSE_COMPLETION_FLAGS
    {
        CF_CALLBACK_CLOSE_COMPLETION_FLAG_NONE = 0x00000000,
        CF_CALLBACK_CLOSE_COMPLETION_FLAG_DELETED = 0x00000001,
    }
    [Flags]
    enum CF_CALLBACK_DEHYDRATE_FLAGS
    {
        CF_CALLBACK_DEHYDRATE_FLAG_NONE = 0x00000000,
        CF_CALLBACK_DEHYDRATE_FLAG_BACKGROUND = 0x00000001,
    }

    [Flags]
    enum CF_CALLBACK_DEHYDRATE_COMPLETION_FLAGS
    {
        CF_CALLBACK_DEHYDRATE_COMPLETION_FLAG_NONE = 0x00000000,
        CF_CALLBACK_DEHYDRATE_COMPLETION_FLAG_BACKGROUND = 0x00000001,
        CF_CALLBACK_DEHYDRATE_COMPLETION_FLAG_DEHYDRATED = 0x00000002,
    }

    [Flags]
    enum CF_CALLBACK_DELETE_FLAGS
    {
        CF_CALLBACK_DELETE_FLAG_NONE = 0x00000000,
        CF_CALLBACK_DELETE_FLAG_IS_DIRECTORY = 0x00000001,
        CF_CALLBACK_DELETE_FLAG_IS_UNDELETE = 0x00000002,
    }

    [Flags]
    enum CF_CALLBACK_DELETE_COMPLETION_FLAGS
    {
        CF_CALLBACK_DELETE_COMPLETION_FLAG_NONE = 0x00000000,
    }

    [Flags]
    enum CF_CALLBACK_RENAME_FLAGS
    {
        CF_CALLBACK_RENAME_FLAG_NONE = 0x00000000,
        CF_CALLBACK_RENAME_FLAG_IS_DIRECTORY = 0x00000001,
        CF_CALLBACK_RENAME_FLAG_SOURCE_IN_SCOPE = 0x00000002,
        CF_CALLBACK_RENAME_FLAG_TARGET_IN_SCOPE = 0x00000004,
    }

    [Flags]
    enum CF_CALLBACK_RENAME_COMPLETION_FLAGS
    {
        CF_CALLBACK_RENAME_COMPLETION_FLAG_NONE = 0x00000000,
    }

    [Flags]
    enum CF_CALLBACK_DEHYDRATION_REASON
    {
        CF_CALLBACK_DEHYDRATION_REASON_NONE,
        CF_CALLBACK_DEHYDRATION_REASON_USER_MANUAL,
        CF_CALLBACK_DEHYDRATION_REASON_SYSTEM_LOW_SPACE,
        CF_CALLBACK_DEHYDRATION_REASON_SYSTEM_INACTIVITY,
        CF_CALLBACK_DEHYDRATION_REASON_SYSTEM_OS_UPGRADE,
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct CF_CALLBACK_PARAMETERS_INNER_CANCEL
    {
        public CF_CALLBACK_CANCEL_FLAGS Flags;
        public LargeIntegerStruct FileOffset; // Can also be Length;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct CF_CALLBACK_PARAMETERS_INNER_VALIDATE_DATA
    {
        public CF_CALLBACK_VALIDATE_DATA_FLAGS Flags;
        public LargeIntegerStruct RequiredFileOffset;
        public LargeIntegerStruct RequiredLength;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct CF_CALLBACK_PARAMETERS_INNER_FETCH_PLACEHOLDERS
    {
        public CF_CALLBACK_FETCH_PLACEHOLDERS_FLAGS Flags;
        public string Pattern;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct CF_CALLBACK_PARAMETERS_INNER_OPEN_COMPLETION
    {
        public CF_CALLBACK_OPEN_COMPLETION_FLAGS Flags;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct CF_CALLBACK_PARAMETERS_INNER_CLOSE_COMPLETION
    {
        public CF_CALLBACK_CLOSE_COMPLETION_FLAGS Flags;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct CF_CALLBACK_PARAMETERS_INNER_DEHYDRATE
    {
        public CF_CALLBACK_DEHYDRATE_FLAGS Flags;
        public CF_CALLBACK_DEHYDRATION_REASON Reason;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct CF_CALLBACK_PARAMETERS_INNER_DEHYDRATE_COMPELTE
    {
        public CF_CALLBACK_DEHYDRATE_COMPLETION_FLAGS Flags;
        public CF_CALLBACK_DEHYDRATION_REASON Reason;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct CF_CALLBACK_PARAMETERS_INNER_DELETE
    {
        public CF_CALLBACK_DELETE_FLAGS Flags;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct CF_CALLBACK_PARAMETERS_INNER_DELETE_COMPLETION
    {
        public CF_CALLBACK_DELETE_COMPLETION_FLAGS Flags;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct CF_CALLBACK_PARAMETERS_INNER_RENAME
    {
        public CF_CALLBACK_RENAME_FLAGS Flags;
        public string TargetPath;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct CF_CALLBACK_PARAMETERS_INNER_RENAME_COMPLETION
    {
        public CF_CALLBACK_RENAME_COMPLETION_FLAGS Flags;
        public string SourcePath;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct CF_CALLBACK_PARAMETERS_INNER_FETCH_DATA
    {
        public CF_CALLBACK_FETCH_DATA_FLAGS Flags;
        public LargeIntegerStruct RequiredFileOffset;
        public LargeIntegerStruct RequiredLength;
        public LargeIntegerStruct OptionalFileOffset;
        public LargeIntegerStruct OptionalLength;
        public LargeIntegerStruct LastDehydrationTime;
        public CF_CALLBACK_DEHYDRATION_REASON LastDehydrationReason;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct CF_CALLBACK_PARAMETERS_FETCH_DATA
    {
        public long ParamSize;
        public CF_CALLBACK_FETCH_DATA_FLAGS Flags;
        public LargeIntegerStruct RequiredFileOffset;
        public LargeIntegerStruct RequiredLength;
        public LargeIntegerStruct OptionalFileOffset;
        public LargeIntegerStruct OptionalLength;
        public LargeIntegerStruct LastDehydrationTime;
        public CF_CALLBACK_DEHYDRATION_REASON LastDehydrationReason;
    }

    [StructLayout(LayoutKind.Explicit)]
    struct CF_CALLBACK_PARAMETERS_INNER
    {
        [FieldOffset(0)]
        public CF_CALLBACK_PARAMETERS_INNER_FETCH_DATA FetchData;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct CF_CALLBACK_PARAMETERS
    {
        public int ParamSize;
        public CF_CALLBACK_PARAMETERS_INNER Params;
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
    delegate void CF_CALLBACK(in CF_CALLBACK_INFO CallbackInfo, IntPtr CallbackParameters);

    enum CF_CALLBACK_TYPE : uint
    {
        CF_CALLBACK_TYPE_FETCH_DATA,
        CF_CALLBACK_TYPE_VALIDATE_DATA,
        CF_CALLBACK_TYPE_CANCEL_FETCH_DATA,
        CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS,
        CF_CALLBACK_TYPE_CANCEL_FETCH_PLACEHOLDERS,
        CF_CALLBACK_TYPE_NOTIFY_FILE_OPEN_COMPLETION,
        CF_CALLBACK_TYPE_NOTIFY_FILE_CLOSE_COMPLETION,
        CF_CALLBACK_TYPE_NOTIFY_DEHYDRATE,
        CF_CALLBACK_TYPE_NOTIFY_DEHYDRATE_COMPLETION,
        CF_CALLBACK_TYPE_NOTIFY_DELETE,
        CF_CALLBACK_TYPE_NOTIFY_DELETE_COMPLETION,
        CF_CALLBACK_TYPE_NOTIFY_RENAME,
        CF_CALLBACK_TYPE_NOTIFY_RENAME_COMPLETION,
        CF_CALLBACK_TYPE_NONE = 0xffffffff
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct CF_CALLBACK_REGISTRATION
    {
        public CF_CALLBACK_TYPE Type;
        [MarshalAs(UnmanagedType.FunctionPtr)]
        public CF_CALLBACK Callback;
    }

    [Flags]
    enum CF_CONNECT_FLAGS
    {
        CF_CONNECT_FLAG_NONE = 0x00000000,
        CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO = 0x00000002,
        CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH = 0x00000004,
        CF_CONNECT_FLAG_BLOCK_SELF_IMPLICIT_HYDRATION = 0x00000008,
    }

    [DllImport("cldapi.dll", CharSet = CharSet.Unicode)]
    static extern int CfConnectSyncRoot(
        string SyncRootPath,
        [MarshalAs(UnmanagedType.LPArray), In] CF_CALLBACK_REGISTRATION[] CallbackTable,
        IntPtr CallbackContext,
        CF_CONNECT_FLAGS ConnectFlags,
        out long ConnectionKey
    );

    [DllImport("cldapi.dll", CharSet = CharSet.Unicode)]
    static extern int CfDisconnectSyncRoot(
        long ConnectionKey
    );

    [DllImport("cldapi.dll", CharSet = CharSet.Unicode)]
    static extern int CfGetTransferKey(
        SafeHandle FileHandle,
        out long TransferKey
    );

    [DllImport("cldapi.dll", CharSet = CharSet.Unicode)]
    static extern void CfReleaseTransferKey(
        SafeHandle FileHandle,
        ref long TransferKey
    );

    [Flags]
    enum CF_CONVERT_FLAGS
    {
        CF_CONVERT_FLAG_NONE = 0x00000000,
        CF_CONVERT_FLAG_MARK_IN_SYNC = 0x00000001,
        CF_CONVERT_FLAG_DEHYDRATE = 0x00000002,
        CF_CONVERT_FLAG_ENABLE_ON_DEMAND_POPULATION = 0x00000004,
        CF_CONVERT_FLAG_ALWAYS_FULL = 0x00000008,
    }

    [Flags]
    enum CF_CREATE_FLAGS
    {
        CF_CREATE_FLAG_NONE = 0x00000000,
        CF_CREATE_FLAG_STOP_ON_ERROR = 0x00000001,
    }

    [DllImport("cldapi.dll", CharSet = CharSet.Unicode)]
    static extern int CfCreatePlaceholders(
        string BaseDirectoryPath,
        [In, Out, MarshalAs(UnmanagedType.LPArray)] CF_PLACEHOLDER_CREATE_INFO[] PlaceholderArray,
        int PlaceholderCount,
        CF_CREATE_FLAGS CreateFlags,
        out int EntriesProcessed
    );

    [DllImport("cldapi.dll", CharSet = CharSet.Unicode)]
    static extern int CfConvertToPlaceholder(
        SafeHandle FileHandle,
        IntPtr FileIdentity,
        int FileIdentityLength,
        CF_CONVERT_FLAGS ConvertFlags,
        out long ConvertUsn,
        IntPtr Overlapped
    );

    enum CF_OPERATION_TYPE
    {
        CF_OPERATION_TYPE_TRANSFER_DATA,
        CF_OPERATION_TYPE_RETRIEVE_DATA,
        CF_OPERATION_TYPE_ACK_DATA,
        CF_OPERATION_TYPE_RESTART_HYDRATION,
        CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS,
        CF_OPERATION_TYPE_ACK_DEHYDRATE,
        CF_OPERATION_TYPE_ACK_DELETE,
        CF_OPERATION_TYPE_ACK_RENAME,
    }

    [StructLayout(LayoutKind.Sequential)]
    struct CF_SYNC_STATUS
    {
        public int StructSize;
        public int Code;
        public int DescriptionOffset;
        public int DescriptionLength;
        public int DeviceIdOffset;
        public int DeviceIdLength;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct CF_OPERATION_INFO
    {
        public int StructSize;
        public CF_OPERATION_TYPE Type;
        public long ConnectionKey;
        public long TransferKey;
        public IntPtr CorrelationVector; // CONST CORRELATION_VECTOR* 
        public IntPtr SyncStatus; // CF_SYNC_STATUS* 
        public long RequestKey;
    }

    enum CF_OPERATION_TRANSFER_DATA_FLAGS
    {
        CF_OPERATION_TRANSFER_DATA_FLAG_NONE = 0x00000000,
    }

    enum CF_OPERATION_RETRIEVE_DATA_FLAGS
    {
        CF_OPERATION_RETRIEVE_DATA_FLAG_NONE = 0x00000000,
    }

    enum CF_OPERATION_ACK_DATA_FLAGS
    {
        CF_OPERATION_ACK_DATA_FLAG_NONE = 0x00000000,
    }

    enum CF_OPERATION_RESTART_HYDRATION_FLAGS
    {
        CF_OPERATION_RESTART_HYDRATION_FLAG_NONE = 0x00000000,
        CF_OPERATION_RESTART_HYDRATION_FLAG_MARK_IN_SYNC = 0x00000001,
    }

    enum CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAGS
    {
        CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_NONE = 0x00000000,
        CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_STOP_ON_ERROR = 0x00000001,
        CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_DISABLE_ON_DEMAND_POPULATION = 0x00000002,
    }

    enum CF_OPERATION_ACK_DEHYDRATE_FLAGS
    {
        CF_OPERATION_ACK_DEHYDRATE_FLAG_NONE = 0x00000000,
    }

    enum CF_OPERATION_ACK_RENAME_FLAGS
    {
        CF_OPERATION_ACK_RENAME_FLAG_NONE = 0x00000000,
    }

    enum CF_OPERATION_ACK_DELETE_FLAGS
    {
        CF_OPERATION_ACK_DELETE_FLAG_NONE = 0x00000000,
    }

    [StructLayout(LayoutKind.Sequential)]
    struct CF_OPERATION_PARAMETERS
    {
        public long ParamSize;
        public CF_OPERATION_TRANSFER_DATA_FLAGS Flags;
        public int CompletionStatus;
        public IntPtr Buffer;
        public LargeIntegerStruct Offset;
        public LargeIntegerStruct Length;
    }

    [DllImport("cldapi.dll", CharSet = CharSet.Unicode)]
    static extern int CfExecute(
        in CF_OPERATION_INFO OpInfo,
        ref CF_OPERATION_PARAMETERS OpParams
    );

    [DllImport("cldapi.dll", CharSet = CharSet.Unicode)]
    static extern int CfUpdateSyncProviderStatus(
        long ConnectionKey,
        CF_SYNC_PROVIDER_STATUS ProviderStatus
    );

    [DllImport("cldapi.dll", CharSet = CharSet.Unicode)]
    static extern int CfQuerySyncProviderStatus(
        long ConnectionKey,
        out CF_SYNC_PROVIDER_STATUS ProviderStatus
    );

    static Guid ProviderId = new Guid("{B196E670-59C7-4D41-9637-C62D80541321}");
    static AutoResetEvent ContinueEvent = new AutoResetEvent(false);
    static bool run = true;
    static bool restart = true;
    static IntPtr nativeCallback = IntPtr.Zero;
    static IntPtr nativeBuffer = IntPtr.Zero;
    static int nativeBufferSize = 0;
    delegate void CFuncDelegate();

    [DllImport("kernel32.dll")]
    static extern void RtlZeroMemory(IntPtr dst, IntPtr length);

    [DllImport("kernel32.dll")]
    static extern void RtlCopyMemory(IntPtr Destination, IntPtr Source, IntPtr Length);

    static int Check(this int hr)
    {
        if (hr < 0)
            Marshal.ThrowExceptionForHR(hr);
        return hr;
    }

    static void DoTransferCallback(in CF_CALLBACK_INFO CallbackInfo, IntPtr CallbackParameters)
    {
        var ps = Marshal.PtrToStructure<CF_CALLBACK_PARAMETERS_FETCH_DATA>(CallbackParameters);

        CF_OPERATION_INFO opInfo = new CF_OPERATION_INFO();
        CF_OPERATION_PARAMETERS opParams = new CF_OPERATION_PARAMETERS();

        try
        {
            opInfo.StructSize = Marshal.SizeOf(opInfo);
            opInfo.Type = CF_OPERATION_TYPE.CF_OPERATION_TYPE_TRANSFER_DATA;
            opInfo.ConnectionKey = CallbackInfo.ConnectionKey;
            opInfo.TransferKey = CallbackInfo.TransferKey;

            int length = (int)ps.RequiredLength.QuadPart;
            int offset = (int)ps.RequiredFileOffset.QuadPart;
            Console.WriteLine("Requesting offset 0x{0:X08} length 0x{1:X08}", offset, length);

            // https://stackoverflow.com/questions/2470487/call-c-function-pointer-from-c-sharp/2472299#2472299
            CFuncDelegate func = (CFuncDelegate)Marshal.GetDelegateForFunctionPointer<CFuncDelegate>(nativeCallback); // IL3050
            IntPtr buffer = Marshal.AllocHGlobal(new IntPtr(length));
            RtlZeroMemory(buffer, new IntPtr(length));
            if (nativeBuffer != IntPtr.Zero && offset == 0) {
                func(); // Native callback
                RtlCopyMemory(buffer, nativeBuffer, nativeBufferSize);
                HexDump(buffer, nativeBufferSize);
            }
            
            try
            {
                opParams.ParamSize = Marshal.SizeOf(opParams);
                opParams.CompletionStatus = 0;
                opParams.Buffer = buffer;
                opParams.Offset = ps.RequiredFileOffset;
                opParams.Length = ps.RequiredLength;

                CfExecute(opInfo, ref opParams).Check();
            
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);

            }
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
        }
    }

    [UnmanagedCallersOnly(EntryPoint = "resume")]
    static void Continue() {
        ContinueEvent.Set();
    }
    
    [UnmanagedCallersOnly(EntryPoint = "restart")]
    static void Restart() {
        run=false;
    }

    [UnmanagedCallersOnly(EntryPoint = "stop")]
    static void Stop() {
        restart = false;
        run=false;
    }

    [UnmanagedCallersOnly(EntryPoint = "set_callback")]
    static void SetCallback(IntPtr fPtr) {
        nativeCallback = fPtr;
    }

    [UnmanagedCallersOnly(EntryPoint = "set_buffer")]
    static void SetBuffer(IntPtr buf, int size) {
        nativeBuffer = buf;
        nativeBufferSize = size;
        Console.WriteLine("[Cf] Native buffer set to:");
        HexDump(nativeBuffer, nativeBufferSize);
    }


    [UnmanagedCallersOnly(EntryPoint="serve")]
    static void Serve(IntPtr dummy)
    {
        try
        {
            string SyncRoot = "C:\\root";
            string FilePath = @"file.bin";

            if (!Directory.Exists(SyncRoot))
            {
                Directory.CreateDirectory(SyncRoot);
            }

            if (File.Exists(Path.Combine(SyncRoot, FilePath)))
            {
                File.Delete(Path.Combine(SyncRoot, FilePath));
            }

            while(restart)
            {
                CF_SYNC_REGISTRATION reg = new CF_SYNC_REGISTRATION();
                reg.StructSize = Marshal.SizeOf(reg);
                reg.ProviderName = "CloudFilterTrapDemo";
                reg.ProviderVersion = "1.0";
                reg.ProviderId = ProviderId;

                CF_SYNC_POLICIES policies = new CF_SYNC_POLICIES();
                policies.StructSize = Marshal.SizeOf(policies);
                policies.HardLink = CF_HARDLINK_POLICY.CF_HARDLINK_POLICY_ALLOWED;
                policies.Hydration = new CF_HYDRATION_POLICY()
                {
                    Primary = CF_HYDRATION_POLICY_PRIMARY.CF_HYDRATION_POLICY_PARTIAL,
                    Modifier = CF_HYDRATION_POLICY_MODIFIER.CF_HYDRATION_POLICY_MODIFIER_NONE
                };
                policies.InSync = CF_INSYNC_POLICY.CF_INSYNC_POLICY_NONE;
                policies.PlaceholderManagement = CF_PLACEHOLDER_MANAGEMENT_POLICY.CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT;
                policies.Population = new CF_POPULATION_POLICY() { Primary = CF_POPULATION_POLICY_PRIMARY.CF_POPULATION_POLICY_PARTIAL };

                CfRegisterSyncRoot(SyncRoot, reg, policies, CF_REGISTER_FLAGS.CF_REGISTER_FLAG_DISABLE_ON_DEMAND_POPULATION_ON_ROOT).Check();

                try
                {
                    CF_CALLBACK_REGISTRATION[] table = new CF_CALLBACK_REGISTRATION[2];
                    table[0] = new CF_CALLBACK_REGISTRATION() { Callback = DoTransferCallback, Type = CF_CALLBACK_TYPE.CF_CALLBACK_TYPE_FETCH_DATA };
                    table[1] = new CF_CALLBACK_REGISTRATION() { Callback = null, Type = CF_CALLBACK_TYPE.CF_CALLBACK_TYPE_NONE };
                    CfConnectSyncRoot(SyncRoot, table, IntPtr.Zero, CF_CONNECT_FLAGS.CF_CONNECT_FLAG_NONE, out long key).Check();
                    try
                    {
                        Console.WriteLine("Key: {0}", key);
                        CF_PLACEHOLDER_CREATE_INFO[] place_holders = new CF_PLACEHOLDER_CREATE_INFO[1];
                        place_holders[0].RelativeFileName = FilePath;
                        CF_FS_METADATA meta_data = new CF_FS_METADATA
                        {
                            FileSize = new LargeIntegerStruct() { QuadPart = 1024 * 1024 * 1024 },
                            BasicInfo = new FileBasicInformation()
                            {
                                FileAttributes = FileAttributes.Normal,
                                CreationTime = new LargeIntegerStruct() { QuadPart = DateTime.Now.ToFileTime() },
                            }
                        };
                        place_holders[0].FsMetadata = meta_data;
                        place_holders[0].Flags = CF_PLACEHOLDER_CREATE_FLAGS.CF_PLACEHOLDER_CREATE_FLAG_SUPERSEDE
                            | CF_PLACEHOLDER_CREATE_FLAGS.CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC;
                        place_holders[0].FileIdentity = Marshal.AllocHGlobal(0x130);
                        place_holders[0].FileIdentityLength = 0x130;
                        CfCreatePlaceholders(SyncRoot, place_holders, 1,
                            CF_CREATE_FLAGS.CF_CREATE_FLAG_STOP_ON_ERROR, out int processed).Check();
                        Console.WriteLine("Started");
                        run = true;
                        while (run)
                        {
                            Thread.Sleep(100);
                        }
                    }
                    finally
                    {
                        CfDisconnectSyncRoot(key);
                    }
                }
                finally
                {
                    CfUnregisterSyncRoot(SyncRoot).Check();
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
        }
    }
}
