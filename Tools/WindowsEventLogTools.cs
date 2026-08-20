using System.ComponentModel;
using System.Globalization;
using System.Runtime.Versioning;
using ModelContextProtocol.Server;
using RemoteAdminMCPSharp.Services;

namespace RemoteAdminMCPSharp.Tools;

/// <summary>Bounded, read-only investigation tools for Windows Event Logs.</summary>
[SupportedOSPlatform("windows")]
[McpServerToolType]
public static class WindowsEventLogTools
{
    private const int MaxChannels = 1_000;
    private const int MaxResults = 500;
    private const int MaxEventsScanned = 50_000;
    private const int MaxMessageChars = 262_144;
    private const int MaxTimeoutSeconds = 120;

    [McpServerTool(Name = "win_list_event_logs"),
     Description("Enumerate Windows Event Log channels on a remote host with enabled/accessibility, record count, size, retention, and provider metadata. Results are bounded and page by channel name.")]
    public static Task<string> ListEventLogsAsync(
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Optional case-insensitive substring filter on channel name or display name")] string? nameContains = null,
        [Description("Include disabled channels. Default false.")] bool includeDisabled = false,
        [Description("Max channels to return. Default 200, hard cap 1000.")] int maxResults = 200,
        [Description("Stable page cursor: the last ChannelName returned by the previous call")] string? continuation = null,
        CancellationToken cancellationToken = default)
    {
        var target = inventory.GetRequired(server);
        var cappedResults = Math.Clamp(maxResults, 1, MaxChannels);

        const string script = """
            param($nameContains, $includeDisabled, $maxResults, $continuation)
            $errors = [System.Collections.Generic.List[string]]::new()
            $channels = @(
                Get-WinEvent -ListLog * -Force -ErrorAction SilentlyContinue -ErrorVariable +listErrors |
                    Where-Object {
                        ($includeDisabled -or $_.IsEnabled) -and
                        (-not $nameContains -or
                            $_.LogName.IndexOf($nameContains, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
                            ($_.LogDisplayName -and $_.LogDisplayName.IndexOf($nameContains, [StringComparison]::OrdinalIgnoreCase) -ge 0)) -and
                        (-not $continuation -or [string]::Compare($_.LogName, $continuation, $true, [Globalization.CultureInfo]::InvariantCulture) -gt 0)
                    } |
                    Sort-Object LogName |
                    Select-Object -First ($maxResults + 1) |
                    ForEach-Object {
                        [PSCustomObject]@{
                            ChannelName       = $_.LogName
                            DisplayName       = $_.LogDisplayName
                            Enabled           = [bool]$_.IsEnabled
                            Accessible        = $true
                            RecordCount       = if ($null -eq $_.RecordCount) { $null } else { [int64]$_.RecordCount }
                            FileSizeBytes     = if ($null -eq $_.FileSize) { $null } else { [int64]$_.FileSize }
                            MaximumSizeBytes  = [int64]$_.MaximumSizeInBytes
                            LastWriteTimeUtc  = if ($_.LastWriteTime) { $_.LastWriteTime.ToUniversalTime().ToString('o') } else { $null }
                            LogMode           = if ($_.LogMode) { $_.LogMode.ToString() } else { $null }
                            Isolation         = if ($_.LogIsolation) { $_.LogIsolation.ToString() } else { $null }
                            Type              = if ($_.LogType) { $_.LogType.ToString() } else { $null }
                            OwningProvider    = $_.OwningProviderName
                            ProviderCount     = if ($_.ProviderNames) { @($_.ProviderNames).Count } else { 0 }
                            ProviderNames     = @($_.ProviderNames | Select-Object -First 100)
                            ProviderListTruncated = (@($_.ProviderNames).Count -gt 100)
                        }
                    }
            )

            foreach ($errorRecord in @($listErrors | Select-Object -First 20)) {
                $errors.Add($errorRecord.ToString())
            }

            $hasMore = $channels.Count -gt $maxResults
            $page = @($channels | Select-Object -First $maxResults)
            [PSCustomObject]@{
                Channels         = $page
                Count            = $page.Count
                HasMore          = $hasMore
                NextContinuation = if ($hasMore -and $page.Count -gt 0) { $page[-1].ChannelName } else { $null }
                Errors           = $errors.ToArray()
                ErrorsTruncated  = (@($listErrors).Count -gt 20)
            }
            """;

        return exec.InvokeRemoteJsonAsync(
            target,
            script,
            new object?[] { nameContains, includeDisabled, cappedResults, continuation },
            jsonDepth: 6,
            cancellationToken: cancellationToken);
    }

    [McpServerTool(Name = "win_search_event_log"),
     Description("Search one live Windows Event Log channel or exported .evtx file. System filters and continuation are applied at the event source; text filtering is bounded by maxEventsScanned. Returns structured fields, rendered messages, diagnostics, and a stable RecordId cursor.")]
    public static Task<string> SearchEventLogAsync(
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Live event-log channel, e.g. System or Microsoft-Windows-PowerShell/Operational. Required unless path is supplied.")] string? channel = null,
        [Description("Absolute path to an exported .evtx file on the remote host. Mutually exclusive with channel.")] string? path = null,
        [Description("Inclusive UTC start time in ISO-8601 format")] string? startTimeUtc = null,
        [Description("Inclusive UTC end time in ISO-8601 format")] string? endTimeUtc = null,
        [Description("Exact provider name")] string? provider = null,
        [Description("Comma-separated event IDs, e.g. 1000,1001")] string? eventIds = null,
        [Description("Comma-separated levels by name or number: Critical/1, Error/2, Warning/3, Information/4, Verbose/5")] string? levels = null,
        [Description("Exact machine name from the event's System/Computer field")] string? machine = null,
        [Description("Optional case-insensitive text contained in the rendered message or event XML")] string? text = null,
        [Description("Max matching events to return. Default 100, hard cap 500.")] int maxResults = 100,
        [Description("Max source-filtered events examined for this page. Default 5000, hard cap 50000.")] int maxEventsScanned = 5_000,
        [Description("Stable cursor from NextContinuationRecordId on the previous page. Reuse the same filters.")] long? continuationRecordId = null,
        [Description("Return oldest events first. Default false (newest first).")] bool oldestFirst = false,
        [Description("Max rendered message characters per event. Default 32768, hard cap 262144.")] int maxMessageChars = 32_768,
        [Description("Operation timeout in seconds. Default 30, hard cap 120.")] int timeoutSeconds = 30,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(channel) == string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("Specify exactly one of channel or path.");
        }

        var parsedStart = ParseUtc(startTimeUtc, nameof(startTimeUtc));
        var parsedEnd = ParseUtc(endTimeUtc, nameof(endTimeUtc));
        if (parsedStart is not null && parsedEnd is not null &&
            string.CompareOrdinal(parsedStart, parsedEnd) > 0)
        {
            throw new ArgumentException("startTimeUtc must be earlier than or equal to endTimeUtc.");
        }

        var parsedEventIds = ParseIntegerList(eventIds, nameof(eventIds), 0, int.MaxValue);
        var parsedLevels = ParseLevels(levels);
        var cappedResults = Math.Clamp(maxResults, 1, MaxResults);
        var cappedScan = Math.Clamp(maxEventsScanned, cappedResults, MaxEventsScanned);
        var cappedMessageChars = Math.Clamp(maxMessageChars, 256, MaxMessageChars);
        var cappedTimeout = Math.Clamp(timeoutSeconds, 1, MaxTimeoutSeconds);
        var target = inventory.GetRequired(server);

        const string script = """
            param(
                $channel, $path, $startUtc, $endUtc, $provider, $eventIds, $levels,
                $machine, $text, $maxResults, $maxEventsScanned, $continuationRecordId,
                $oldestFirst, $maxMessageChars
            )

            function ConvertTo-XPathLiteral([string]$value) {
                if ($value.IndexOf("'") -lt 0) { return "'$value'" }
                if ($value.IndexOf('"') -lt 0) { return '"' + $value + '"' }
                $parts = $value -split "'", -1
                $expressions = [System.Collections.Generic.List[string]]::new()
                for ($i = 0; $i -lt $parts.Count; $i++) {
                    if ($parts[$i].Length -gt 0) { $expressions.Add("'$($parts[$i])'") }
                    if ($i -lt ($parts.Count - 1)) { $expressions.Add('"''"') }
                }
                return 'concat(' + ($expressions -join ',') + ')'
            }

            $predicates = [System.Collections.Generic.List[string]]::new()
            if ($provider) {
                $predicates.Add('(Provider[@Name=' + (ConvertTo-XPathLiteral $provider) + '])')
            }
            if ($eventIds -and $eventIds.Count -gt 0) {
                $predicates.Add('(' + (($eventIds | ForEach-Object { 'EventID=' + [int]$_ }) -join ' or ') + ')')
            }
            if ($levels -and $levels.Count -gt 0) {
                $predicates.Add('(' + (($levels | ForEach-Object { 'Level=' + [int]$_ }) -join ' or ') + ')')
            }
            if ($startUtc) { $predicates.Add("TimeCreated[@SystemTime >= '$startUtc']") }
            if ($endUtc) { $predicates.Add("TimeCreated[@SystemTime <= '$endUtc']") }
            if ($machine) {
                $predicates.Add('(Computer=' + (ConvertTo-XPathLiteral $machine) + ')')
            }
            if ($null -ne $continuationRecordId) {
                $comparison = if ($oldestFirst) { '>' } else { '<' }
                $predicates.Add("EventRecordID $comparison $continuationRecordId")
            }

            $xpath = if ($predicates.Count -eq 0) {
                '*'
            } else {
                '*[System[' + ($predicates -join ' and ') + ']]'
            }

            $query = @{
                FilterXPath = $xpath
                MaxEvents   = $maxEventsScanned
                Oldest      = [bool]$oldestFirst
                ErrorAction = 'Stop'
            }
            if ($path) { $query['Path'] = $path } else { $query['LogName'] = $channel }

            $results = [System.Collections.Generic.List[object]]::new()
            $scanned = 0
            $lastScannedRecordId = $null
            $renderFailures = 0
            $queryError = $null

            try {
                Get-WinEvent @query |
                    Where-Object {
                        $scanned++
                        $lastScannedRecordId = $_.RecordId
                        if (-not $text) { return $true }
                        $rendered = $null
                        try { $rendered = $_.Message } catch { }
                        if ($rendered -and $rendered.IndexOf($text, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                            return $true
                        }
                        try {
                            return $_.ToXml().IndexOf($text, [StringComparison]::OrdinalIgnoreCase) -ge 0
                        } catch { return $false }
                    } |
                    Select-Object -First $maxResults |
                    ForEach-Object {
                        $event = $_
                        $message = $null
                        $renderError = $null
                        try { $message = $event.Message } catch {
                            $renderFailures++
                            $renderError = $_.Exception.Message
                        }
                        $messageTruncated = $message -and $message.Length -gt $maxMessageChars
                        if ($messageTruncated) { $message = $message.Substring(0, $maxMessageChars) }

                        $eventData = [ordered]@{}
                        $userDataXml = $null
                        $xmlError = $null
                        try {
                            [xml]$xml = $event.ToXml()
                            $index = 0
                            foreach ($data in @($xml.Event.EventData.Data)) {
                                $name = if ($data.Name) { [string]$data.Name } else { "Data$index" }
                                $value = [string]$data.'#text'
                                if ($null -eq $value) { $value = [string]$data }
                                if ($value.Length -gt $maxMessageChars) {
                                    $value = $value.Substring(0, $maxMessageChars)
                                }
                                $eventData[$name] = $value
                                $index++
                            }
                            if ($xml.Event.UserData) { $userDataXml = $xml.Event.UserData.InnerXml }
                            if ($userDataXml -and $userDataXml.Length -gt $maxMessageChars) {
                                $userDataXml = $userDataXml.Substring(0, $maxMessageChars)
                            }
                        } catch { $xmlError = $_.Exception.Message }

                        $results.Add([PSCustomObject]@{
                            RecordId        = if ($null -eq $event.RecordId) { $null } else { [int64]$event.RecordId }
                            TimeCreatedUtc  = if ($event.TimeCreated) { $event.TimeCreated.ToUniversalTime().ToString('o') } else { $null }
                            EventId         = [int]$event.Id
                            Version         = $event.Version
                            Level           = $event.Level
                            LevelName       = $event.LevelDisplayName
                            Task            = $event.Task
                            TaskName        = $event.TaskDisplayName
                            Opcode          = $event.Opcode
                            OpcodeName      = $event.OpcodeDisplayName
                            Keywords        = $event.Keywords
                            KeywordNames    = @($event.KeywordsDisplayNames)
                            ProviderName    = $event.ProviderName
                            ProviderId      = $event.ProviderId
                            Channel         = $event.LogName
                            Machine         = $event.MachineName
                            ProcessId       = $event.ProcessId
                            ThreadId        = $event.ThreadId
                            UserId          = if ($event.UserId) { $event.UserId.Value } else { $null }
                            ActivityId      = $event.ActivityId
                            RelatedActivityId = $event.RelatedActivityId
                            Message         = $message
                            MessageTruncated = [bool]$messageTruncated
                            RenderError     = $renderError
                            EventData       = [PSCustomObject]$eventData
                            UserDataXml     = $userDataXml
                            XmlError        = $xmlError
                        })
                    }
            } catch [System.Diagnostics.Eventing.Reader.EventLogNotFoundException] {
                $queryError = "Event log or exported file not found: $($_.Exception.Message)"
            } catch [System.UnauthorizedAccessException] {
                $queryError = "Access denied while reading the event log: $($_.Exception.Message)"
            } catch [System.Diagnostics.Eventing.Reader.EventLogReadingException] {
                $queryError = "The event log is malformed or unreadable: $($_.Exception.Message)"
            } catch {
                if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
                    $queryError = $_.Exception.Message
                }
            }

            $hasMore = ($results.Count -ge $maxResults) -or ($scanned -ge $maxEventsScanned)
            [PSCustomObject]@{
                Source                   = if ($path) { $path } else { $channel }
                SourceType               = if ($path) { 'evtx' } else { 'channel' }
                OldestFirst              = [bool]$oldestFirst
                XPath                    = $xpath
                Events                   = $results.ToArray()
                Returned                 = $results.Count
                Scanned                  = $scanned
                ScanLimitReached         = ($scanned -ge $maxEventsScanned)
                HasMore                  = $hasMore
                NextContinuationRecordId = if ($hasMore) { $lastScannedRecordId } else { $null }
                RenderFailures           = $renderFailures
                Error                    = $queryError
            }
            """;

        return exec.InvokeRemoteJsonAsync(
            target,
            script,
            new object?[]
            {
                channel?.Trim(), path?.Trim(), parsedStart, parsedEnd, provider?.Trim(),
                parsedEventIds, parsedLevels, machine?.Trim(), text, cappedResults, cappedScan,
                continuationRecordId, oldestFirst, cappedMessageChars,
            },
            jsonDepth: 8,
            timeout: TimeSpan.FromSeconds(cappedTimeout),
            cancellationToken: cancellationToken);
    }

    private static string? ParseUtc(string? value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        if (!DateTimeOffset.TryParse(
                value,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var parsed))
        {
            throw new ArgumentException($"{parameterName} must be a valid ISO-8601 timestamp.");
        }

        return parsed.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture);
    }

    private static int[] ParseIntegerList(
        string? value,
        string parameterName,
        int minimum,
        int maximum)
    {
        if (string.IsNullOrWhiteSpace(value)) return [];

        var values = new HashSet<int>();
        foreach (var part in value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            if (!int.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) ||
                parsed < minimum || parsed > maximum)
            {
                throw new ArgumentException(
                    $"{parameterName} contains invalid value '{part}'. Expected integers from {minimum} to {maximum}.");
            }
            values.Add(parsed);
        }

        return values.Order().ToArray();
    }

    private static int[] ParseLevels(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return [];

        var mapped = new List<int>();
        foreach (var part in value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            var level = part.ToUpperInvariant() switch
            {
                "CRITICAL" => 1,
                "ERROR" => 2,
                "WARNING" => 3,
                "INFORMATION" or "INFO" => 4,
                "VERBOSE" => 5,
                _ when int.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out var numeric) => numeric,
                _ => -1,
            };

            if (level is < 0 or > 5)
            {
                throw new ArgumentException(
                    $"levels contains invalid value '{part}'. Use Critical, Error, Warning, Information, Verbose, or 0-5.");
            }
            mapped.Add(level);
        }

        return mapped.Distinct().Order().ToArray();
    }
}
