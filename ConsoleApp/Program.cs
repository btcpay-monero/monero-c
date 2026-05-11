using System.Runtime.InteropServices;

namespace ConsoleApp;

internal partial class Program
{
    public static void Main()
    {
        if (!monero_utils_is_valid_language("English"))
        {
            throw new Exception("Validation error");
        }

        if (monero_utils_is_valid_language("english"))
        {
            throw new Exception("Validation error");
        }

        Console.WriteLine("Ok!");
        Console.ReadLine();
    }

    [LibraryImport("NativeLib")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool monero_utils_is_valid_language([MarshalAs(UnmanagedType.LPUTF8Str)] string language);
}
