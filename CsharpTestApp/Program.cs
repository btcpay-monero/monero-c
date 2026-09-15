using System.Text.Json;

namespace CsharpTestApp;

internal class Program
{
    public static void Main()
    {
        Console.WriteLine("Main - started");

        IntPtr daemon = MoneroInterop.ConnectDaemon("http://127.0.0.1:18081");
        if (daemon == IntPtr.Zero)
        {
            throw new Exception($"Failed to connect to daemon: {MoneroInterop.GetError()}");
        }

        string? infoJson = MoneroInterop.GetDaemonInfo(daemon);
        if (infoJson == null)
        {
            throw new Exception($"get_info failed: {MoneroInterop.GetError()}");
        }

        Console.WriteLine(infoJson);

        using JsonDocument doc = JsonDocument.Parse(infoJson);
        string? version = doc.RootElement.GetProperty("version").GetString();

        const string expectedVersion = "0.18.5.1-release";
        if (version != expectedVersion)
        {
            throw new Exception($"Unexpected daemon version: expected '{expectedVersion}', got '{version}'");
        }
        Console.WriteLine($"Version assertion passed: {version}");

        MoneroInterop.FreeDaemon(daemon);
    }
}