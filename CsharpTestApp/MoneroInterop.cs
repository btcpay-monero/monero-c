using System.Runtime.InteropServices;

namespace CsharpTestApp;

internal static class MoneroInterop
{
    internal static string? GetError() =>
        PtrToStringAndFree(NativeMethods.monero_get_error());

    internal static string? GetDaemonInfo(IntPtr daemon) =>
        PtrToStringAndFree(NativeMethods.monero_daemon_get_info(daemon));

    internal static IntPtr ConnectDaemon(string uri, string username = "", string password = "", string proxyUri = "", string zmqUri = "") =>
        NativeMethods.monero_daemon_connect(uri, username, password, proxyUri, zmqUri);

    internal static void FreeDaemon(IntPtr daemon) =>
        NativeMethods.monero_daemon_free(daemon);

    private static string? PtrToStringAndFree(IntPtr ptr)
    {
        if (ptr == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            return Marshal.PtrToStringUTF8(ptr);
        }
        finally
        {
            NativeMethods.monero_free_string(ptr);
        }
    }
}