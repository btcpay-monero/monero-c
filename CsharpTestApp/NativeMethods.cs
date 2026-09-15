using System.Runtime.InteropServices;

namespace CsharpTestApp;

internal static partial class NativeMethods
{
    [LibraryImport("monero-c")]
    internal static partial IntPtr monero_daemon_connect(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string uri,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string username,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string password,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string proxyUri,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string zmqUri);

    [LibraryImport("monero-c")]
    internal static partial void monero_daemon_free(IntPtr daemon);

    [LibraryImport("monero-c")]
    internal static partial IntPtr monero_daemon_get_info(IntPtr daemon);

    [LibraryImport("monero-c")]
    internal static partial IntPtr monero_get_error();

    [LibraryImport("monero-c")]
    internal static partial void monero_free_string(IntPtr str);
}