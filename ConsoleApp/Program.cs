using System.Runtime.InteropServices;

namespace ConsoleApp;

internal partial class Program
{
    public static void Main()
    {
        HelloWorld();
        Console.ReadLine();
    }

    [LibraryImport("NativeLib")]
    private static partial void HelloWorld();
}