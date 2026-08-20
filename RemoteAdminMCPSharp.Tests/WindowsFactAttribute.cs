using Xunit;

namespace RemoteAdminMCPSharp.Tests;

public sealed class WindowsFactAttribute : FactAttribute
{
    public WindowsFactAttribute()
    {
        if (!OperatingSystem.IsWindows())
        {
            Skip = "Requires Windows PowerShell and Windows file-handle semantics.";
        }
    }
}
