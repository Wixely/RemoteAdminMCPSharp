using System.Management.Automation;
using System.Runtime.Versioning;
using System.Text;
using RemoteAdminMCPSharp.Tools;
using Xunit;

namespace RemoteAdminMCPSharp.Tests;

[SupportedOSPlatform("windows")]
public sealed class WindowsLargeFileSearchScriptTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        $"RemoteAdminMCPSharp.Tests-{Guid.NewGuid():N}");

    public WindowsLargeFileSearchScriptTests() => Directory.CreateDirectory(_directory);

    [WindowsFact]
    public void LiteralSearchReturnsContextOffsetsAndStableContinuation()
    {
        var path = WriteFile(
            "paged.log",
            "alpha\r\nbeta MATCH\r\ngamma\r\nmatch two\r\nomega",
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));

        var first = Invoke(path, "match", contextLines: 1, maxMatches: 1);

        Assert.Equal("Ok", Value<string>(first, "Status"));
        var firstMatch = Assert.Single(Array(first, "Matches"));
        Assert.Equal(2L, Value<long>(firstMatch, "LineNumber"));
        Assert.Equal("beta MATCH", Value<string>(firstMatch, "Text"));
        Assert.Equal(10L, Value<long>(firstMatch, "ByteOffset"));
        Assert.Equal("alpha", Value<string>(Assert.Single(Array(firstMatch, "Before")), "Text"));
        Assert.Equal("gamma", Value<string>(Assert.Single(Array(firstMatch, "After")), "Text"));
        Assert.True(Value<bool>(first, "MatchLimitReached"));

        var second = Invoke(
            path,
            "match",
            contextLines: 1,
            maxMatches: 1,
            continuationOffset: Value<long>(first, "NextOffset"),
            continuationLineNumber: Value<long>(first, "NextLineNumber"),
            snapshotLengthBytes: Value<long>(first, "SnapshotLengthBytes"),
            expectedFileIdentity: Value<string>(first, "FileIdentity"));

        var secondMatch = Assert.Single(Array(second, "Matches"));
        Assert.Equal(4L, Value<long>(secondMatch, "LineNumber"));
        Assert.Equal("match two", Value<string>(secondMatch, "Text"));
    }

    [WindowsFact]
    public void RegexSearchSupportsUtf16AndByteOffsets()
    {
        var path = WriteFile(
            "utf16.log",
            "first\r\nError 123\r\nlast\r\n",
            new UnicodeEncoding(bigEndian: false, byteOrderMark: true));

        var result = Invoke(
            path,
            @"error\s+\d+",
            useRegex: true,
            encoding: "auto");

        Assert.Equal("utf16le", Value<string>(result, "Encoding"));
        Assert.True(Value<bool>(result, "ByteOffsetsReliable"));
        var match = Assert.Single(Array(result, "Matches"));
        Assert.Equal(2L, Value<long>(match, "LineNumber"));
        Assert.Equal(16L, Value<long>(match, "ByteOffset"));
        Assert.Equal("Error 123", Value<string>(match, "Text"));
    }

    [WindowsFact]
    public void SnapshotDoesNotSearchContentAppendedAfterFirstPage()
    {
        var path = WriteFile("growth.log", "start\r\n", new UTF8Encoding(false));
        var first = Invoke(path, "missing");

        File.AppendAllText(path, "new MATCH\r\n", new UTF8Encoding(false));
        var second = Invoke(
            path,
            "match",
            continuationOffset: Value<long>(first, "NextOffset"),
            continuationLineNumber: Value<long>(first, "NextLineNumber"),
            snapshotLengthBytes: Value<long>(first, "SnapshotLengthBytes"),
            expectedFileIdentity: Value<string>(first, "FileIdentity"));

        Assert.Empty(Array(second, "Matches"));
        Assert.True(Value<bool>(second, "GrowthDetected"));
    }

    [WindowsFact]
    public void ContinuationDetectsReplacementBeforeResuming()
    {
        var path = WriteFile("rotating.log", "before rotation\r\n", new UTF8Encoding(false));
        var first = Invoke(path, "missing");
        var rotated = Path.Combine(_directory, "rotating.log.1");
        File.Move(path, rotated);
        File.WriteAllText(path, "replacement MATCH\r\n", new UTF8Encoding(false));

        var second = Invoke(
            path,
            "match",
            continuationOffset: Value<long>(first, "NextOffset"),
            continuationLineNumber: Value<long>(first, "NextLineNumber"),
            snapshotLengthBytes: Value<long>(first, "SnapshotLengthBytes"),
            expectedFileIdentity: Value<string>(first, "FileIdentity"));

        Assert.Equal("Replaced", Value<string>(second, "Status"));
        Assert.True(Value<bool>(second, "ReplacementDetected"));
        Assert.Empty(Array(second, "Matches"));
    }

    [WindowsFact]
    public void ContinuationDetectsInPlaceTruncation()
    {
        var path = WriteFile("truncated.log", "line one\r\nline two\r\n", new UTF8Encoding(false));
        var first = Invoke(path, "missing");
        using (var writer = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite))
        {
            writer.SetLength(4);
        }

        var second = Invoke(
            path,
            "line",
            continuationOffset: 0,
            continuationLineNumber: 1,
            snapshotLengthBytes: Value<long>(first, "SnapshotLengthBytes"),
            expectedFileIdentity: Value<string>(first, "FileIdentity"));

        Assert.Equal("Truncated", Value<string>(second, "Status"));
        Assert.True(Value<bool>(second, "TruncationDetected"));
    }

    [WindowsFact]
    public async Task FollowModeFindsCompatibleAppend()
    {
        var path = WriteFile("follow.log", "start\r\n", new UTF8Encoding(false));

        var scan = Task.Run(() => Invoke(
            path,
            "arrived",
            mode: "follow",
            maxMatches: 1,
            maxElapsedMilliseconds: 5_000));
        await Task.Delay(300);
        File.AppendAllText(path, "ARRIVED\r\n", new UTF8Encoding(false));

        var result = await scan;
        Assert.Equal("ARRIVED", Value<string>(Assert.Single(Array(result, "Matches")), "Text"));
        Assert.True(Value<bool>(result, "GrowthDetected"));
    }

    [WindowsFact]
    public void ExclusiveLockReturnsClearDiagnostic()
    {
        var path = WriteFile("locked.log", "content\r\n", new UTF8Encoding(false));
        using var locked = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);

        var result = Invoke(path, "content");

        Assert.Equal("Inaccessible", Value<string>(result, "Status"));
        Assert.Contains("FileShare.ReadWrite | FileShare.Delete", Value<string>(result, "Error"));
    }

    [WindowsFact]
    public void InvalidBytesAreReportedWithoutCrashing()
    {
        var path = Path.Combine(_directory, "invalid-utf8.log");
        File.WriteAllBytes(path, [0x66, 0x6f, 0x80, 0x6f, 0x0a]);

        var result = Invoke(path, "foo", encoding: "utf8");

        Assert.Equal("Ok", Value<string>(result, "Status"));
        Assert.Equal(1L, Value<long>(result, "DecodingFailures"));
        Assert.Empty(Array(result, "Matches"));
    }

    [WindowsFact]
    public void MatchingUsesTheLineScanLimitRatherThanTheSmallerDisplayLimit()
    {
        var path = WriteFile(
            "long-line.log",
            new string('x', 9_000) + "NEEDLE\r\n",
            new UTF8Encoding(false));

        var result = Invoke(path, "needle", maxReturnedLineChars: 1_024);

        var match = Assert.Single(Array(result, "Matches"));
        Assert.True(Value<bool>(match, "TextTruncated"));
        Assert.False(Value<bool>(match, "LineTruncated"));
    }

    [WindowsFact]
    public async Task StoppingThePipelineCancelsFollowAndReleasesTheFilePromptly()
    {
        var path = WriteFile("cancel.log", "start\r\n", new UTF8Encoding(false));
        _ = Invoke(path, "warm-up"); // Compile the target-side type before measuring cancellation.

        using var powershell = CreateInvocation(
            path,
            "never-arrives",
            mode: "follow",
            maxElapsedMilliseconds: 30_000);
        _ = powershell.BeginInvoke();
        await Task.Delay(300);

        await Task.Run(powershell.Stop).WaitAsync(TimeSpan.FromSeconds(3));

        using var exclusive = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        Assert.True(exclusive.CanWrite);
    }

    [WindowsFact]
    public void Utf16NewlineDetectionRespectsCodeUnitAlignment()
    {
        var path = WriteFile(
            "utf16-alignment.log",
            "\u0a01\u0100 NEEDLE\r\nlast\r\n",
            new UnicodeEncoding(bigEndian: false, byteOrderMark: true));

        var result = Invoke(path, "needle", encoding: "utf16le");

        Assert.Equal("Ok", Value<string>(result, "Status"));
        var match = Assert.Single(Array(result, "Matches"));
        Assert.Equal(1L, Value<long>(match, "LineNumber"));
        Assert.Equal("\u0a01\u0100 NEEDLE", Value<string>(match, "Text"));
        Assert.Equal(0L, Value<long>(result, "DecodingFailures"));
    }

    [WindowsFact]
    public void ByteLimitInsideLineReturnsExplicitNonPageableDiagnostic()
    {
        var path = WriteFile(
            "page-limit-mid-line.log",
            "a line longer than the page limit\r\nNEEDLE\r\n",
            new UTF8Encoding(false));

        var result = Invoke(path, "needle", maxBytesToScan: 8);

        Assert.Equal("LimitReachedMidLine", Value<string>(result, "Status"));
        Assert.True(Value<bool>(result, "ByteLimitReached"));
        Assert.True(Value<bool>(result, "ContinuationBlocked"));
        Assert.True(Value<bool>(result, "HasMore"));
        Assert.Equal(0L, Value<long>(result, "NextOffset"));
        Assert.Contains("no lossless continuation", Value<string>(result, "Error"));
    }

    [WindowsFact]
    public void MisalignedMultibyteContinuationIsRejected()
    {
        var path = WriteFile(
            "misaligned-continuation.log",
            "first\r\nsecond\r\n",
            new UnicodeEncoding(bigEndian: false, byteOrderMark: true));

        var result = Invoke(
            path,
            "second",
            encoding: "utf16le",
            continuationOffset: 3);

        Assert.Equal("InvalidContinuation", Value<string>(result, "Status"));
        Assert.True(Value<bool>(result, "ContinuationBlocked"));
        Assert.Empty(Array(result, "Matches"));
    }

    private string WriteFile(string name, string contents, Encoding encoding)
    {
        var path = Path.Combine(_directory, name);
        File.WriteAllText(path, contents, encoding);
        return path;
    }

    private static PSObject Invoke(
        string path,
        string pattern,
        bool useRegex = false,
        string encoding = "auto",
        int contextLines = 0,
        int maxMatches = 50,
        string mode = "snapshot",
        int maxElapsedMilliseconds = 3_000,
        long continuationOffset = 0,
        long continuationLineNumber = 1,
        long snapshotLengthBytes = -1,
        string? expectedFileIdentity = null,
        int maxReturnedLineChars = 8_192,
        long maxBytesToScan = 16L * 1024 * 1024)
    {
        using var powershell = CreateInvocation(
            path,
            pattern,
            useRegex,
            encoding,
            contextLines,
            maxMatches,
            mode,
            maxElapsedMilliseconds,
            continuationOffset,
            continuationLineNumber,
            snapshotLengthBytes,
            expectedFileIdentity,
            maxReturnedLineChars,
            maxBytesToScan);

        var output = powershell.Invoke();
        if (powershell.HadErrors)
        {
            throw new Xunit.Sdk.XunitException(
                string.Join(Environment.NewLine, powershell.Streams.Error.Select(error => error.ToString())));
        }

        return Assert.Single(output);
    }

    private static PowerShell CreateInvocation(
        string path,
        string pattern,
        bool useRegex = false,
        string encoding = "auto",
        int contextLines = 0,
        int maxMatches = 50,
        string mode = "snapshot",
        int maxElapsedMilliseconds = 3_000,
        long continuationOffset = 0,
        long continuationLineNumber = 1,
        long snapshotLengthBytes = -1,
        string? expectedFileIdentity = null,
        int maxReturnedLineChars = 8_192,
        long maxBytesToScan = 16L * 1024 * 1024)
    {
        var powershell = PowerShell.Create();
        powershell.AddScript(WindowsLargeFileSearchTools.SearchScript)
            .AddArgument(path)
            .AddArgument(pattern)
            .AddArgument(useRegex)
            .AddArgument(false)
            .AddArgument(encoding)
            .AddArgument(contextLines)
            .AddArgument(maxMatches)
            .AddArgument(maxBytesToScan)
            .AddArgument(65_536)
            .AddArgument(maxReturnedLineChars)
            .AddArgument(maxElapsedMilliseconds)
            .AddArgument(250)
            .AddArgument(mode)
            .AddArgument(continuationOffset)
            .AddArgument(continuationLineNumber)
            .AddArgument(snapshotLengthBytes)
            .AddArgument(expectedFileIdentity);
        return powershell;
    }

    private static T Value<T>(PSObject value, string property) =>
        Assert.IsAssignableFrom<T>(value.Properties[property].Value);

    private static PSObject[] Array(PSObject value, string property) =>
        Assert.IsAssignableFrom<IEnumerable<object>>(value.Properties[property].Value)
            .Select(item => Assert.IsType<PSObject>(PSObject.AsPSObject(item)))
            .ToArray();

    public void Dispose()
    {
        if (Directory.Exists(_directory)) Directory.Delete(_directory, recursive: true);
    }
}
