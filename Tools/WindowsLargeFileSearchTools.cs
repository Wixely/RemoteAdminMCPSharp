using System.ComponentModel;
using System.Runtime.Versioning;
using ModelContextProtocol.Server;
using RemoteAdminMCPSharp.Services;

namespace RemoteAdminMCPSharp.Tools;

/// <summary>Bounded, streaming text search for large files on remote Windows hosts.</summary>
[SupportedOSPlatform("windows")]
[McpServerToolType]
public static class WindowsLargeFileSearchTools
{
    private const int MaxMatches = 100;
    private const int MaxContextLines = 5;
    private const int MaxLineBytes = 1024 * 1024;
    private const int MaxReturnedLineChars = 32_768;
    private const long MaxBytesScanned = 2L * 1024 * 1024 * 1024;
    private const int MaxElapsedSeconds = 120;
    private const int MaxRegexTimeoutMilliseconds = 2_000;

    [McpServerTool(Name = "win_search_large_file"),
     Description("Search a very large text file on a remote Windows host without loading it into memory. Supports literal/regex matching, common encodings, context, byte-accurate continuation, snapshot/follow modes, permissive read sharing, and explicit lock/rotation/truncation/decoding diagnostics.")]
    public static Task<string> SearchLargeFileAsync(
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Absolute path to the text file on the remote host")] string path,
        [Description("Literal text or regular expression to find")] string pattern,
        [Description("Interpret pattern as a regular expression. Default false (literal search).")] bool useRegex = false,
        [Description("Use case-sensitive matching. Default false.")] bool caseSensitive = false,
        [Description("Encoding: auto, utf8, ascii, latin1, utf16le/unicode, utf16be, utf32le, or utf32be. Default auto (BOM, otherwise UTF-8).")] string encoding = "auto",
        [Description("Lines of context before and after each match. Default 0, hard cap 5.")] int contextLines = 0,
        [Description("Max matches returned. Default 50, hard cap 100.")] int maxMatches = 50,
        [Description("Max bytes examined in this page. Default 268435456 (256 MiB), hard cap 2 GiB.")] long maxBytesToScan = 256L * 1024 * 1024,
        [Description("Max bytes retained from an individual line for matching. Default 65536, hard cap 1 MiB; longer lines are flagged.")] int maxLineBytes = 65_536,
        [Description("Max characters returned for each match/context line. Default 8192, hard cap 32768.")] int maxReturnedLineChars = 8_192,
        [Description("Max scan time in seconds. Default 30, hard cap 120.")] int maxElapsedSeconds = 30,
        [Description("Per-line regular-expression timeout in milliseconds. Default 250, hard cap 2000.")] int regexTimeoutMilliseconds = 250,
        [Description("Growth behavior: snapshot searches the starting length; follow waits for appended complete lines until a limit is reached. Default snapshot.")] string mode = "snapshot",
        [Description("Continuation byte offset returned as NextOffset by the previous page. Default 0.")] long continuationOffset = 0,
        [Description("Continuation line number returned as NextLineNumber by the previous page. Default 1.")] long continuationLineNumber = 1,
        [Description("SnapshotLengthBytes returned by the first snapshot page. Supply it on later pages to preserve the same starting-length view.")] long? snapshotLengthBytes = null,
        [Description("FileIdentity returned by the previous page. Supply it to detect replacement/rotation before resuming.")] string? expectedFileIdentity = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("path is required.", nameof(path));
        if (string.IsNullOrEmpty(pattern))
            throw new ArgumentException("pattern must not be empty.", nameof(pattern));

        var normalizedMode = mode.Trim().ToLowerInvariant();
        if (normalizedMode is not ("snapshot" or "follow"))
            throw new ArgumentException("mode must be 'snapshot' or 'follow'.", nameof(mode));
        if (snapshotLengthBytes is < 0)
            throw new ArgumentOutOfRangeException(nameof(snapshotLengthBytes));

        var target = inventory.GetRequired(server);
        var cappedContext = Math.Clamp(contextLines, 0, MaxContextLines);
        var cappedMatches = Math.Clamp(maxMatches, 1, MaxMatches);
        var cappedBytes = Math.Clamp(maxBytesToScan, 1, MaxBytesScanned);
        var cappedLineBytes = Math.Clamp(maxLineBytes, 256, MaxLineBytes);
        var cappedReturnedChars = Math.Clamp(maxReturnedLineChars, 128, MaxReturnedLineChars);
        var cappedElapsed = Math.Clamp(maxElapsedSeconds, 1, MaxElapsedSeconds);
        var cappedRegexTimeout = Math.Clamp(
            regexTimeoutMilliseconds,
            1,
            MaxRegexTimeoutMilliseconds);

        return exec.InvokeRemoteJsonAsync(
            target,
            SearchScript,
            new object?[]
            {
                path.Trim(), pattern, useRegex, caseSensitive, encoding.Trim(), cappedContext,
                cappedMatches, cappedBytes, cappedLineBytes, cappedReturnedChars,
                cappedElapsed * 1_000, cappedRegexTimeout, normalizedMode,
                Math.Max(0, continuationOffset), Math.Max(1, continuationLineNumber),
                snapshotLengthBytes ?? -1, expectedFileIdentity,
            },
            jsonDepth: 8,
            timeout: TimeSpan.FromSeconds(cappedElapsed + 10),
            cancellationToken: cancellationToken);
    }

    // The scanner runs on the target so only bounded matches cross WinRM. It uses raw newline
    // sequences rather than StreamReader buffering, which makes byte offsets stable for every
    // supported encoding and lets it reject oversized lines without allocating them in full.
    internal const string SearchScript = """
        param(
            $path, $pattern, $useRegex, $caseSensitive, $encoding, $contextLines,
            $maxMatches, $maxBytesToScan, $maxLineBytes, $maxReturnedLineChars,
            $maxElapsedMilliseconds, $regexTimeoutMilliseconds, $mode,
            $continuationOffset, $continuationLineNumber, $snapshotLengthBytes,
            $expectedFileIdentity
        )

        if (-not ('RemoteAdminMCPSharp.RemoteScripts.LargeFileScanner' -as [type])) {
            Add-Type -TypeDefinition @'
        using System;
        using System.Collections.Generic;
        using System.Diagnostics;
        using System.Globalization;
        using System.IO;
        using System.Runtime.InteropServices;
        using System.Text;
        using System.Text.RegularExpressions;
        using System.Threading;
        using System.Threading.Tasks;
        using Microsoft.Win32.SafeHandles;

        namespace RemoteAdminMCPSharp.RemoteScripts
        {
            public sealed class SearchLine
            {
                public long LineNumber { get; set; }
                public long ByteOffset { get; set; }
                public long ByteLength { get; set; }
                public string Text { get; set; }
                public bool LineTruncated { get; set; }
                public bool TextTruncated { get; set; }
                public bool Incomplete { get; set; }
                public bool DecodingError { get; set; }
                internal string FullText;
            }

            public sealed class SearchMatch
            {
                public long LineNumber { get; set; }
                public long ByteOffset { get; set; }
                public long ByteLength { get; set; }
                public string Text { get; set; }
                public bool LineTruncated { get; set; }
                public bool TextTruncated { get; set; }
                public bool Incomplete { get; set; }
                public bool DecodingError { get; set; }
                public SearchLine[] Before { get; set; }
                public SearchLine[] After { get; set; }
            }

            public sealed class SearchResult
            {
                public string Status { get; set; }
                public string Error { get; set; }
                public string Path { get; set; }
                public string Mode { get; set; }
                public string Encoding { get; set; }
                public bool ByteOffsetsReliable { get; set; }
                public string FileIdentity { get; set; }
                public long StartingLengthBytes { get; set; }
                public long SnapshotLengthBytes { get; set; }
                public long StartOffset { get; set; }
                public long NextOffset { get; set; }
                public long NextLineNumber { get; set; }
                public long BytesScanned { get; set; }
                public long LinesScanned { get; set; }
                public SearchMatch[] Matches { get; set; }
                public int MatchCount { get; set; }
                public bool MatchLimitReached { get; set; }
                public bool ByteLimitReached { get; set; }
                public bool TimeLimitReached { get; set; }
                public bool ContinuationBlocked { get; set; }
                public bool HasMore { get; set; }
                public bool GrowthDetected { get; set; }
                public bool TruncationDetected { get; set; }
                public bool ReplacementDetected { get; set; }
                public bool IncompleteTrailingRecord { get; set; }
                public long OversizedLines { get; set; }
                public long DecodingFailures { get; set; }
                public long RegexTimeouts { get; set; }
            }

            internal sealed class PendingMatch
            {
                internal SearchMatch Match;
                internal int Remaining;
                internal long ContinuationOffset;
                internal long ContinuationLineNumber;
            }

            internal sealed class ReadOutcome
            {
                internal SearchLine Line;
                internal bool EndOfInput;
                internal bool PartialLine;
                internal long PartialLineOffset;
                internal bool ByteLimit;
                internal bool TimeLimit;
                internal bool Truncated;
                internal bool Replaced;
            }

            public sealed class SearchOperation : IDisposable
            {
                private readonly CancellationTokenSource cancellation = new CancellationTokenSource();
                public Task<SearchResult> Task { get; private set; }

                internal SearchOperation(Func<CancellationToken, SearchResult> search)
                {
                    Task = System.Threading.Tasks.Task.Factory.StartNew(
                        delegate { return search(cancellation.Token); },
                        cancellation.Token,
                        TaskCreationOptions.DenyChildAttach,
                        TaskScheduler.Default);
                }

                public void Dispose()
                {
                    cancellation.Cancel();
                    try { Task.Wait(5000); }
                    catch (AggregateException exception)
                    {
                        exception.Handle(delegate(Exception inner) {
                            return inner is OperationCanceledException;
                        });
                    }
                    finally { cancellation.Dispose(); }
                }
            }

            public static class LargeFileScanner
            {
                [StructLayout(LayoutKind.Sequential)]
                private struct FileTime
                {
                    internal uint Low;
                    internal uint High;
                }

                [StructLayout(LayoutKind.Sequential)]
                private struct ByHandleFileInformation
                {
                    internal uint FileAttributes;
                    internal FileTime CreationTime;
                    internal FileTime LastAccessTime;
                    internal FileTime LastWriteTime;
                    internal uint VolumeSerialNumber;
                    internal uint FileSizeHigh;
                    internal uint FileSizeLow;
                    internal uint NumberOfLinks;
                    internal uint FileIndexHigh;
                    internal uint FileIndexLow;
                }

                [DllImport("kernel32.dll", SetLastError = true)]
                private static extern bool GetFileInformationByHandle(
                    SafeFileHandle handle,
                    out ByHandleFileInformation information);

                public static SearchOperation StartSearch(
                    string path,
                    string pattern,
                    bool useRegex,
                    bool caseSensitive,
                    string encodingName,
                    int contextLines,
                    int maxMatches,
                    long maxBytesToScan,
                    int maxLineBytes,
                    int maxReturnedLineChars,
                    int maxElapsedMilliseconds,
                    int regexTimeoutMilliseconds,
                    string mode,
                    long continuationOffset,
                    long continuationLineNumber,
                    long requestedSnapshotLength,
                    string expectedFileIdentity)
                {
                    return new SearchOperation(delegate(CancellationToken cancellationToken) {
                        return Search(
                            path, pattern, useRegex, caseSensitive, encodingName, contextLines,
                            maxMatches, maxBytesToScan, maxLineBytes, maxReturnedLineChars,
                            maxElapsedMilliseconds, regexTimeoutMilliseconds, mode,
                            continuationOffset, continuationLineNumber, requestedSnapshotLength,
                            expectedFileIdentity, cancellationToken);
                    });
                }

                private static SearchResult Search(
                    string path,
                    string pattern,
                    bool useRegex,
                    bool caseSensitive,
                    string encodingName,
                    int contextLines,
                    int maxMatches,
                    long maxBytesToScan,
                    int maxLineBytes,
                    int maxReturnedLineChars,
                    int maxElapsedMilliseconds,
                    int regexTimeoutMilliseconds,
                    string mode,
                    long continuationOffset,
                    long continuationLineNumber,
                    long requestedSnapshotLength,
                    string expectedFileIdentity,
                    CancellationToken cancellationToken)
                {
                    SearchResult result = NewResult(path, mode);
                    Stopwatch stopwatch = Stopwatch.StartNew();
                    FileStream stream = null;
                    try
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        stream = new FileStream(
                            path,
                            FileMode.Open,
                            FileAccess.Read,
                            FileShare.ReadWrite | FileShare.Delete,
                            65536,
                            FileOptions.SequentialScan);

                        result.FileIdentity = GetIdentity(stream);
                        result.StartingLengthBytes = stream.Length;
                        result.SnapshotLengthBytes = requestedSnapshotLength >= 0
                            ? requestedSnapshotLength
                            : stream.Length;

                        if (!String.IsNullOrEmpty(expectedFileIdentity) &&
                            !String.Equals(expectedFileIdentity, result.FileIdentity, StringComparison.OrdinalIgnoreCase))
                        {
                            result.Status = "Replaced";
                            result.ReplacementDetected = true;
                            result.Error = "The path now identifies a different file. Restart from offset 0 instead of applying the old continuation.";
                            return result;
                        }

                        EncodingInfo encoding = ResolveEncoding(stream, encodingName, continuationOffset);
                        result.Encoding = encoding.Name;
                        result.ByteOffsetsReliable = true;

                        long startOffset = continuationOffset == 0
                            ? encoding.PreambleLength
                            : continuationOffset;
                        result.StartOffset = startOffset;
                        result.NextOffset = startOffset;
                        result.NextLineNumber = continuationLineNumber;

                        if (startOffset % encoding.UnitSize != 0)
                        {
                            result.Status = "InvalidContinuation";
                            result.ContinuationBlocked = true;
                            result.Error = "The continuation offset is not aligned to a complete " +
                                encoding.Name + " code unit. Reuse an offset returned by this tool.";
                            return result;
                        }

                        long snapshotEnd = Math.Min(result.SnapshotLengthBytes, result.StartingLengthBytes);
                        if (requestedSnapshotLength >= 0 &&
                            result.StartingLengthBytes < requestedSnapshotLength)
                        {
                            result.TruncationDetected = true;
                        }
                        if (continuationOffset > snapshotEnd && mode == "snapshot")
                        {
                            result.Status = "Truncated";
                            result.TruncationDetected = true;
                            result.Error = "The continuation offset is beyond the available starting-length snapshot.";
                            return result;
                        }

                        stream.Position = Math.Min(startOffset, stream.Length);
                        Regex regex = null;
                        if (useRegex)
                        {
                            RegexOptions options = RegexOptions.CultureInvariant;
                            if (!caseSensitive) options |= RegexOptions.IgnoreCase;
                            try
                            {
                                regex = new Regex(
                                    pattern,
                                    options,
                                    TimeSpan.FromMilliseconds(regexTimeoutMilliseconds));
                            }
                            catch (ArgumentException exception)
                            {
                                result.Status = "InvalidPattern";
                                result.Error = exception.Message;
                                return result;
                            }
                        }

                        Queue<SearchLine> before = new Queue<SearchLine>();
                        List<PendingMatch> pending = new List<PendingMatch>();
                        List<SearchMatch> matches = new List<SearchMatch>();
                        long lineNumber = continuationLineNumber;
                        bool stopStartingMatches = false;
                        long matchContinuationOffset = -1;
                        long matchContinuationLine = -1;

                        while (true)
                        {
                            cancellationToken.ThrowIfCancellationRequested();
                            ReadOutcome read = ReadLine(
                                stream,
                                path,
                                result.FileIdentity,
                                encoding,
                                mode,
                                snapshotEnd,
                                result.StartOffset > Int64.MaxValue - maxBytesToScan
                                    ? Int64.MaxValue
                                    : result.StartOffset + maxBytesToScan,
                                maxLineBytes,
                                maxReturnedLineChars,
                                lineNumber,
                                stopwatch,
                                maxElapsedMilliseconds,
                                result,
                                cancellationToken);

                            if (read.Replaced) result.ReplacementDetected = true;
                            if (read.Truncated) result.TruncationDetected = true;
                            if (read.ByteLimit) result.ByteLimitReached = true;
                            if (read.TimeLimit) result.TimeLimitReached = true;

                            if (read.Line == null)
                            {
                                if (read.PartialLine)
                                {
                                    result.IncompleteTrailingRecord = true;
                                    result.NextOffset = read.PartialLineOffset;
                                    result.NextLineNumber = lineNumber;
                                    if (read.ByteLimit || read.TimeLimit)
                                    {
                                        result.Status = "LimitReachedMidLine";
                                        result.ContinuationBlocked = true;
                                        result.Error = "The scan limit was reached before the current line ended, " +
                                            "so no lossless continuation is available. Increase maxBytesToScan " +
                                            "or maxElapsedSeconds and retry this page.";
                                    }
                                }
                                break;
                            }

                            SearchLine line = read.Line;
                            result.LinesScanned++;
                            if (line.LineTruncated) result.OversizedLines++;
                            if (line.DecodingError) result.DecodingFailures++;
                            if (line.Incomplete) result.IncompleteTrailingRecord = true;

                            for (int i = pending.Count - 1; i >= 0; i--)
                            {
                                PendingMatch item = pending[i];
                                List<SearchLine> after = new List<SearchLine>(item.Match.After);
                                after.Add(line);
                                item.Match.After = after.ToArray();
                                item.Remaining--;
                                if (item.Remaining <= 0)
                                {
                                    matches.Add(item.Match);
                                    pending.RemoveAt(i);
                                }
                            }

                            if (!stopStartingMatches && !line.DecodingError)
                            {
                                bool isMatch = false;
                                if (regex != null)
                                {
                                    try { isMatch = regex.IsMatch(line.FullText); }
                                    catch (RegexMatchTimeoutException) { result.RegexTimeouts++; }
                                }
                                else
                                {
                                    StringComparison comparison = caseSensitive
                                        ? StringComparison.Ordinal
                                        : StringComparison.OrdinalIgnoreCase;
                                    isMatch = line.FullText.IndexOf(pattern, comparison) >= 0;
                                }

                                if (isMatch)
                                {
                                    SearchMatch match = new SearchMatch
                                    {
                                        LineNumber = line.LineNumber,
                                        ByteOffset = line.ByteOffset,
                                        ByteLength = line.ByteLength,
                                        Text = line.Text,
                                        LineTruncated = line.LineTruncated,
                                        TextTruncated = line.TextTruncated,
                                        Incomplete = line.Incomplete,
                                        DecodingError = line.DecodingError,
                                        Before = before.ToArray(),
                                        After = new SearchLine[0]
                                    };
                                    PendingMatch pendingMatch = new PendingMatch
                                    {
                                        Match = match,
                                        Remaining = contextLines,
                                        ContinuationOffset = stream.Position,
                                        ContinuationLineNumber = lineNumber + 1
                                    };

                                    if (contextLines == 0) matches.Add(match);
                                    else pending.Add(pendingMatch);

                                    if (matches.Count + pending.Count >= maxMatches)
                                    {
                                        result.MatchLimitReached = true;
                                        stopStartingMatches = true;
                                        matchContinuationOffset = stream.Position;
                                        matchContinuationLine = lineNumber + 1;
                                    }
                                }
                            }

                            // Matching is complete for this line. Context and returned matches only
                            // retain the bounded display text, not the larger matching buffer.
                            line.FullText = null;

                            if (contextLines > 0)
                            {
                                before.Enqueue(line);
                                while (before.Count > contextLines) before.Dequeue();
                            }

                            lineNumber++;
                            result.NextOffset = stream.Position;
                            result.NextLineNumber = lineNumber;

                            if (stopStartingMatches && pending.Count == 0) break;
                            if (read.EndOfInput) break;
                        }

                        foreach (PendingMatch item in pending) matches.Add(item.Match);
                        if (matches.Count > maxMatches) matches.RemoveRange(maxMatches, matches.Count - maxMatches);

                        if (result.MatchLimitReached && matchContinuationOffset >= 0)
                        {
                            // Context may have read ahead. Resume immediately after the last match
                            // so matches that appeared in that context are not skipped next page.
                            result.NextOffset = matchContinuationOffset;
                            result.NextLineNumber = matchContinuationLine;
                        }

                        result.Matches = matches.ToArray();
                        result.MatchCount = matches.Count;
                        result.BytesScanned = Math.Max(0, stream.Position - result.StartOffset);

                        long currentHandleLength = stream.Length;
                        if (currentHandleLength < result.StartingLengthBytes || currentHandleLength < stream.Position)
                            result.TruncationDetected = true;
                        if (currentHandleLength > result.SnapshotLengthBytes)
                            result.GrowthDetected = true;

                        string pathIdentity = TryGetPathIdentity(path);
                        if (pathIdentity != null &&
                            !String.Equals(pathIdentity, result.FileIdentity, StringComparison.OrdinalIgnoreCase))
                            result.ReplacementDetected = true;

                        long logicalEnd = mode == "snapshot" ? snapshotEnd : currentHandleLength;
                        result.HasMore = result.MatchLimitReached ||
                            result.ByteLimitReached ||
                            result.TimeLimitReached ||
                            result.NextOffset < logicalEnd ||
                            result.ReplacementDetected ||
                            result.TruncationDetected;

                        if (result.ReplacementDetected)
                        {
                            result.Status = "Replaced";
                            result.Error = "The path was replaced or rotated during the scan; NextOffset refers to the originally opened file.";
                        }
                        else if (result.TruncationDetected)
                        {
                            result.Status = "Truncated";
                            result.Error = "The opened file was truncated during the scan.";
                        }
                        return result;
                    }
                    catch (FileNotFoundException exception)
                    {
                        result.Status = "NotFound";
                        result.Error = exception.Message;
                        return result;
                    }
                    catch (DirectoryNotFoundException exception)
                    {
                        result.Status = "NotFound";
                        result.Error = exception.Message;
                        return result;
                    }
                    catch (UnauthorizedAccessException exception)
                    {
                        result.Status = "AccessDenied";
                        result.Error = exception.Message;
                        return result;
                    }
                    catch (IOException exception)
                    {
                        result.Status = "Inaccessible";
                        result.Error = "The file could not be opened with read access and FileShare.ReadWrite | FileShare.Delete. " +
                            "It may be exclusively locked or an I/O error occurred: " + exception.Message;
                        return result;
                    }
                    catch (OperationCanceledException)
                    {
                        result.Status = "Cancelled";
                        result.Error = "The file search was cancelled.";
                        return result;
                    }
                    catch (Exception exception)
                    {
                        result.Status = "Error";
                        result.Error = exception.GetType().Name + ": " + exception.Message;
                        return result;
                    }
                    finally
                    {
                        if (stream != null) stream.Dispose();
                    }
                }

                private static ReadOutcome ReadLine(
                    FileStream stream,
                    string path,
                    string originalIdentity,
                    EncodingInfo encoding,
                    string mode,
                    long snapshotEnd,
                    long byteLimitOffset,
                    int maxLineBytes,
                    int maxReturnedLineChars,
                    long lineNumber,
                    Stopwatch stopwatch,
                    int maxElapsedMilliseconds,
                    SearchResult result,
                    CancellationToken cancellationToken)
                {
                    ReadOutcome outcome = new ReadOutcome();
                    long lineOffset = stream.Position;
                    MemoryStream stored = new MemoryStream(Math.Min(maxLineBytes, 65536));
                    byte[] tail = new byte[encoding.NewLine.Length];
                    int tailCount = 0;
                    long rawLength = 0;
                    bool oversized = false;

                    while (true)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        long availableEnd = mode == "snapshot"
                            ? Math.Min(snapshotEnd, stream.Length)
                            : stream.Length;
                        availableEnd = Math.Min(availableEnd, byteLimitOffset);

                        while (stream.Position < availableEnd)
                        {
                            if (stopwatch.ElapsedMilliseconds >= maxElapsedMilliseconds)
                            {
                                outcome.TimeLimit = true;
                                outcome.PartialLine = rawLength > 0;
                                outcome.PartialLineOffset = lineOffset;
                                return outcome;
                            }

                            int value = stream.ReadByte();
                            if (value < 0) break;
                            byte current = (byte)value;
                            rawLength++;
                            if ((rawLength & 4095) == 0)
                                cancellationToken.ThrowIfCancellationRequested();

                            if (stored.Length < maxLineBytes)
                                stored.WriteByte(current);
                            else
                                oversized = true;

                            if (tailCount < tail.Length)
                            {
                                tail[tailCount++] = current;
                            }
                            else
                            {
                                Buffer.BlockCopy(tail, 1, tail, 0, tail.Length - 1);
                                tail[tail.Length - 1] = current;
                            }

                            if (tailCount == tail.Length &&
                                rawLength % encoding.UnitSize == 0 &&
                                EndsWith(tail, encoding.NewLine))
                            {
                                long contentLength = rawLength - encoding.NewLine.Length;
                                bool storedEntireLine = rawLength <= maxLineBytes;
                                if (storedEntireLine)
                                    TrimSuffix(stored, encoding.NewLine.Length);
                                if (storedEntireLine && EndsWith(stored, encoding.CarriageReturn))
                                {
                                    contentLength -= encoding.CarriageReturn.Length;
                                    TrimSuffix(stored, encoding.CarriageReturn.Length);
                                }
                                outcome.Line = MakeLine(
                                    stored,
                                    encoding,
                                    lineNumber,
                                    lineOffset,
                                    contentLength,
                                    oversized || contentLength > maxLineBytes,
                                    false,
                                    maxReturnedLineChars);
                                return outcome;
                            }
                        }

                        if (stream.Position >= byteLimitOffset)
                        {
                            outcome.ByteLimit = true;
                            outcome.PartialLine = rawLength > 0;
                            outcome.PartialLineOffset = lineOffset;
                            return outcome;
                        }

                        if (mode == "snapshot")
                        {
                            if (stream.Length < snapshotEnd) outcome.Truncated = true;
                            if (rawLength > 0)
                            {
                                outcome.Line = MakeLine(
                                    stored,
                                    encoding,
                                    lineNumber,
                                    lineOffset,
                                    rawLength,
                                    oversized || rawLength > maxLineBytes,
                                    true,
                                    maxReturnedLineChars);
                                outcome.EndOfInput = true;
                            }
                            else outcome.EndOfInput = true;
                            return outcome;
                        }

                        if (stopwatch.ElapsedMilliseconds >= maxElapsedMilliseconds)
                        {
                            outcome.TimeLimit = true;
                            outcome.PartialLine = rawLength > 0;
                            outcome.PartialLineOffset = lineOffset;
                            return outcome;
                        }
                        if (stream.Length < stream.Position)
                        {
                            outcome.Truncated = true;
                            outcome.PartialLine = rawLength > 0;
                            outcome.PartialLineOffset = lineOffset;
                            return outcome;
                        }
                        string currentIdentity = TryGetPathIdentity(path);
                        if (currentIdentity != null &&
                            !String.Equals(currentIdentity, originalIdentity, StringComparison.OrdinalIgnoreCase))
                        {
                            outcome.Replaced = true;
                            outcome.PartialLine = rawLength > 0;
                            outcome.PartialLineOffset = lineOffset;
                            return outcome;
                        }
                        if (cancellationToken.WaitHandle.WaitOne(200))
                            cancellationToken.ThrowIfCancellationRequested();
                    }
                }

                private static SearchLine MakeLine(
                    MemoryStream stored,
                    EncodingInfo encoding,
                    long lineNumber,
                    long byteOffset,
                    long byteLength,
                    bool truncated,
                    bool incomplete,
                    int maxReturnedLineChars)
                {
                    byte[] bytes = stored.ToArray();
                    string text;
                    bool decodingError = false;
                    try
                    {
                        text = encoding.Strict.GetString(bytes);
                    }
                    catch (DecoderFallbackException)
                    {
                        if (truncated)
                        {
                            int unit = encoding.UnitSize;
                            int usable = bytes.Length - (bytes.Length % unit);
                            bool decoded = false;
                            text = String.Empty;
                            for (int trim = 0; trim <= Math.Min(4, usable); trim += unit)
                            {
                                try
                                {
                                    text = encoding.Strict.GetString(bytes, 0, usable - trim);
                                    decoded = true;
                                    break;
                                }
                                catch (DecoderFallbackException) { }
                            }
                            if (!decoded)
                            {
                                decodingError = true;
                                text = encoding.Replacement.GetString(bytes);
                            }
                        }
                        else
                        {
                            decodingError = true;
                            text = encoding.Replacement.GetString(bytes);
                        }
                    }

                    bool characterTruncated = text.Length > maxReturnedLineChars;
                    string fullText = text;
                    if (characterTruncated) text = fullText.Substring(0, maxReturnedLineChars);

                    return new SearchLine
                    {
                        LineNumber = lineNumber,
                        ByteOffset = byteOffset,
                        ByteLength = byteLength,
                        Text = text,
                        LineTruncated = truncated,
                        TextTruncated = characterTruncated,
                        Incomplete = incomplete,
                        DecodingError = decodingError,
                        FullText = fullText
                    };
                }

                private static bool EndsWith(byte[] value, byte[] suffix)
                {
                    if (value.Length < suffix.Length) return false;
                    int offset = value.Length - suffix.Length;
                    for (int i = 0; i < suffix.Length; i++)
                        if (value[offset + i] != suffix[i]) return false;
                    return true;
                }

                private static bool EndsWith(MemoryStream stream, byte[] suffix)
                {
                    if (stream.Length < suffix.Length) return false;
                    byte[] buffer = stream.GetBuffer();
                    int offset = (int)stream.Length - suffix.Length;
                    for (int i = 0; i < suffix.Length; i++)
                        if (buffer[offset + i] != suffix[i]) return false;
                    return true;
                }

                private static void TrimSuffix(MemoryStream stream, int count)
                {
                    stream.SetLength(Math.Max(0, stream.Length - count));
                }

                private static SearchResult NewResult(string path, string mode)
                {
                    return new SearchResult
                    {
                        Status = "Ok",
                        Path = path,
                        Mode = mode,
                        Encoding = null,
                        Matches = new SearchMatch[0]
                    };
                }

                private static string GetIdentity(FileStream stream)
                {
                    ByHandleFileInformation information;
                    if (!GetFileInformationByHandle(stream.SafeFileHandle, out information))
                        throw new IOException("GetFileInformationByHandle failed with Win32 error " +
                            Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture) + ".");
                    ulong index = ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow;
                    return information.VolumeSerialNumber.ToString("X8", CultureInfo.InvariantCulture) + ":" +
                        index.ToString("X16", CultureInfo.InvariantCulture);
                }

                private static string TryGetPathIdentity(string path)
                {
                    try
                    {
                        using (FileStream current = new FileStream(
                            path,
                            FileMode.Open,
                            FileAccess.Read,
                            FileShare.ReadWrite | FileShare.Delete))
                        {
                            return GetIdentity(current);
                        }
                    }
                    catch { return null; }
                }

                private sealed class EncodingInfo
                {
                    internal string Name;
                    internal Encoding Strict;
                    internal Encoding Replacement;
                    internal byte[] NewLine;
                    internal byte[] CarriageReturn;
                    internal int PreambleLength;
                    internal int UnitSize;
                }

                private static EncodingInfo ResolveEncoding(
                    FileStream stream,
                    string requested,
                    long continuationOffset)
                {
                    string normalized = (requested ?? "auto").Trim().ToLowerInvariant().Replace("-", "");
                    byte[] prefix = new byte[4];
                    long saved = stream.Position;
                    stream.Position = 0;
                    int count = stream.Read(prefix, 0, prefix.Length);
                    stream.Position = saved;

                    int preamble = 0;
                    string selected = normalized;
                    if (normalized == "auto")
                    {
                        if (count >= 4 && prefix[0] == 0xFF && prefix[1] == 0xFE && prefix[2] == 0 && prefix[3] == 0)
                        { selected = "utf32le"; preamble = 4; }
                        else if (count >= 4 && prefix[0] == 0 && prefix[1] == 0 && prefix[2] == 0xFE && prefix[3] == 0xFF)
                        { selected = "utf32be"; preamble = 4; }
                        else if (count >= 3 && prefix[0] == 0xEF && prefix[1] == 0xBB && prefix[2] == 0xBF)
                        { selected = "utf8"; preamble = 3; }
                        else if (count >= 2 && prefix[0] == 0xFF && prefix[1] == 0xFE)
                        { selected = "utf16le"; preamble = 2; }
                        else if (count >= 2 && prefix[0] == 0xFE && prefix[1] == 0xFF)
                        { selected = "utf16be"; preamble = 2; }
                        else selected = "utf8";
                    }

                    Encoding strict;
                    Encoding replacement;
                    int unitSize;
                    switch (selected)
                    {
                        case "utf8":
                        case "utf8bom":
                            strict = new UTF8Encoding(false, true);
                            replacement = new UTF8Encoding(false, false);
                            unitSize = 1;
                            if (preamble == 0 && count >= 3 && prefix[0] == 0xEF && prefix[1] == 0xBB && prefix[2] == 0xBF) preamble = 3;
                            selected = "utf8";
                            break;
                        case "ascii":
                            strict = Encoding.GetEncoding(20127, EncoderFallback.ExceptionFallback, DecoderFallback.ExceptionFallback);
                            replacement = Encoding.ASCII;
                            unitSize = 1;
                            break;
                        case "latin1":
                        case "iso88591":
                            strict = Encoding.GetEncoding(28591, EncoderFallback.ExceptionFallback, DecoderFallback.ExceptionFallback);
                            replacement = Encoding.GetEncoding(28591);
                            unitSize = 1;
                            selected = "latin1";
                            break;
                        case "unicode":
                        case "utf16le":
                            strict = new UnicodeEncoding(false, false, true);
                            replacement = new UnicodeEncoding(false, false, false);
                            unitSize = 2;
                            if (preamble == 0 && count >= 2 && prefix[0] == 0xFF && prefix[1] == 0xFE) preamble = 2;
                            selected = "utf16le";
                            break;
                        case "bigendianunicode":
                        case "utf16be":
                            strict = new UnicodeEncoding(true, false, true);
                            replacement = new UnicodeEncoding(true, false, false);
                            unitSize = 2;
                            if (preamble == 0 && count >= 2 && prefix[0] == 0xFE && prefix[1] == 0xFF) preamble = 2;
                            selected = "utf16be";
                            break;
                        case "utf32":
                        case "utf32le":
                            strict = new UTF32Encoding(false, false, true);
                            replacement = new UTF32Encoding(false, false, false);
                            unitSize = 4;
                            if (preamble == 0 && count >= 4 && prefix[0] == 0xFF && prefix[1] == 0xFE && prefix[2] == 0 && prefix[3] == 0) preamble = 4;
                            selected = "utf32le";
                            break;
                        case "utf32be":
                            strict = new UTF32Encoding(true, false, true);
                            replacement = new UTF32Encoding(true, false, false);
                            unitSize = 4;
                            if (preamble == 0 && count >= 4 && prefix[0] == 0 && prefix[1] == 0 && prefix[2] == 0xFE && prefix[3] == 0xFF) preamble = 4;
                            selected = "utf32be";
                            break;
                        default:
                            throw new ArgumentException("Unsupported encoding '" + requested + "'.");
                    }

                    if (continuationOffset > 0) preamble = 0;
                    return new EncodingInfo
                    {
                        Name = selected,
                        Strict = strict,
                        Replacement = replacement,
                        NewLine = strict.GetBytes("\n"),
                        CarriageReturn = strict.GetBytes("\r"),
                        PreambleLength = preamble,
                        UnitSize = unitSize
                    };
                }
            }
        }
        '@
        }

        $operation = [RemoteAdminMCPSharp.RemoteScripts.LargeFileScanner]::StartSearch(
            [string]$path,
            [string]$pattern,
            [bool]$useRegex,
            [bool]$caseSensitive,
            [string]$encoding,
            [int]$contextLines,
            [int]$maxMatches,
            [int64]$maxBytesToScan,
            [int]$maxLineBytes,
            [int]$maxReturnedLineChars,
            [int]$maxElapsedMilliseconds,
            [int]$regexTimeoutMilliseconds,
            [string]$mode,
            [int64]$continuationOffset,
            [int64]$continuationLineNumber,
            [int64]$snapshotLengthBytes,
            [string]$expectedFileIdentity)
        try {
            while (-not $operation.Task.Wait(200)) { }
            $operation.Task.GetAwaiter().GetResult()
        } finally {
            $operation.Dispose()
        }
        """;
}
