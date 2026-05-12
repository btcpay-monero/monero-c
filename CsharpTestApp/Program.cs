using System.Runtime.InteropServices;

namespace CsharpTestApp;

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

    [LibraryImport("monero-c")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool monero_utils_is_valid_language([MarshalAs(UnmanagedType.LPUTF8Str)] string language);
}