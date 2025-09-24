# Find correlated events
    $correlated = $sysmonEvents | Where-Object {
        $eventTime = if ($_.LocalTime) { $_.LocalTime } else { $_.TimeCreated }
        $eventTime -ge $windowStart -and $eventTime -le $windowEnd
    }# ===================================
# Simplified Discord-Sysmon Correlation Script
# Focused on Event ID 1 (Process Creation) and Event ID 13 (Registry Value Set)
# Filtered for Discord Cloudflare traffic patterns
# ===================================

# Helper function to parse Suricata timestamps with timezone support
function Parse-SuricataTimestamp {
    param([string]$timestamp)
    
    try {
        # Handle ISO8601 with timezone (e.g., "2025-09-23T14:29:35.048300-0600")
        if ($timestamp -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*[+-]\d{4}$') {
            return [System.DateTimeOffset]::Parse($timestamp).DateTime
        }
        else {
            return [datetime]::Parse($timestamp)
        }
    }
    catch {
        Write-Warning "Failed to parse timestamp: $timestamp"
        return $null
    }
}

# Helper function to check if IP is in Discord IP ranges
function Test-DiscordIP {
    param(
        [string]$ipAddress,
        [switch]$skipVmCheck
    )
    
    try {
        # Check if it's the VM IP (unless we're specifically skipping this check)
        if (-not $skipVmCheck -and $ipAddress -eq "10.0.2.4") {
            return $true
        }
        
        # Parse the IP address
        $ip = [System.Net.IPAddress]::Parse($ipAddress)
        $ipBytes = $ip.GetAddressBytes()
        
        # Check 162.159.0.0/16 (162.159.0.0 - 162.159.255.255)
        if ($ipBytes[0] -eq 162 -and $ipBytes[1] -eq 159) {
            return $true
        }
        
        # Check 104.16.0.0/12 (104.16.0.0 - 104.31.255.255)
        if ($ipBytes[0] -eq 104 -and $ipBytes[1] -ge 16 -and $ipBytes[1] -le 31) {
            return $true
        }
        
        return $false
    }
    catch {
        Write-Warning "Failed to parse IP address: $ipAddress - $_"
        return $false
    }
}

# Configuration
$eveJsonPath = "C:\<Path\To\Your>\eve.json"
$outputDir = "C:\Users\<Your User>\CorrelationResults"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$csvOutput = "$outputDir\Discord_Correlation_$timestamp.csv"
$jsonOutput = "$outputDir\Discord_Correlation_$timestamp.json"
$textOutput = "$outputDir\Discord_Correlation_$timestamp.txt"

# Ensure output directory exists
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

Write-Host "Discord WebSocket to Sysmon Correlation Analysis" -ForegroundColor Yellow
Write-Host "Focusing on Process Creation (ID 1) and Registry Value Set (ID 13)" -ForegroundColor Gray
Write-Host "Output directory: $outputDir" -ForegroundColor Gray

# ===================================
# Load Discord WebSocket Alerts (IP Filtered)
# ===================================
Write-Host "`nLoading Discord WebSocket alerts..." -ForegroundColor Yellow

try {
    if (-not (Test-Path $eveJsonPath)) {
        Write-Error "Suricata log file not found: $eveJsonPath"
        exit 1
    }
    
    $discordAlerts = @()
    Get-Content $eveJsonPath | ForEach-Object { 
        try {
            $json = $_ | ConvertFrom-Json
            if ($json.event_type -eq "alert" -and $json.alert.signature -eq "Discord WebSocket early detection") {
                
                # Check if one IP is VM IP and the other is in Discord ranges
                $hasVmIP = ($json.src_ip -eq "10.0.2.4") -or ($json.dest_ip -eq "10.0.2.4")
                $hasDiscordIP = $false
                
                # Check the non-VM IP to see if it's in Discord ranges
                if ($json.src_ip -eq "10.0.2.4") {
                    # Source is VM, check if destination is Discord
                    $hasDiscordIP = Test-DiscordIP -ipAddress $json.dest_ip -skipVmCheck
                } elseif ($json.dest_ip -eq "10.0.2.4") {
                    # Destination is VM, check if source is Discord  
                    $hasDiscordIP = Test-DiscordIP -ipAddress $json.src_ip -skipVmCheck
                }
                
                $isDiscordTraffic = $hasVmIP -and $hasDiscordIP
                
                if ($isDiscordTraffic) {
                    $parsedTime = Parse-SuricataTimestamp -timestamp $json.timestamp
                    if ($parsedTime) {
                        $discordAlerts += [PSCustomObject]@{
                            OriginalTimestamp = $json.timestamp
                            ParsedTimestamp = $parsedTime
                            SourceIP = $json.src_ip
                            SourcePort = $json.src_port
                            DestIP = $json.dest_ip
                            DestPort = $json.dest_port
                            Proto = $json.proto
                            FlowId = $json.flow_id
                            Direction = if($json.src_ip -eq "10.0.2.4") { "Outbound" } else { "Inbound" }
                        }
                    }
                }
            }
        }
        catch {
            # Skip malformed JSON lines
        }
    }
    
    if ($discordAlerts.Count -eq 0) {
        Write-Warning "No Discord alerts found matching IP criteria"
        Write-Host "Looking for traffic involving:" -ForegroundColor Yellow
        Write-Host "  - VM IP: 10.0.2.4" -ForegroundColor Gray
        Write-Host "  - Cloudflare Range 1: 162.159.0.0/16" -ForegroundColor Gray  
        Write-Host "  - Cloudflare Range 2: 104.16.0.0/12" -ForegroundColor Gray
        exit 0
    }
    
    Write-Host "Found $($discordAlerts.Count) Discord alerts matching IP criteria" -ForegroundColor Green
}
catch {
    Write-Error "Failed to load Suricata alerts: $_"
    exit 1
}

# ===================================
# Load Sysmon Events (ID 1 and 13 only)
# ===================================
Write-Host "`nQuerying Sysmon events (Process Creation and Registry Value Set)..." -ForegroundColor Yellow

try {
    # Calculate time range
    $allAlertTimes = $discordAlerts | Select-Object -ExpandProperty ParsedTimestamp
    $earliestTime = ($allAlertTimes | Measure-Object -Minimum).Minimum.AddMinutes(-2)
    $latestTime = ($allAlertTimes | Measure-Object -Maximum).Maximum.AddMinutes(2)
    
    Write-Host "Time range: $earliestTime to $latestTime" -ForegroundColor Gray
    
    # Query Sysmon events directly - only IDs 1 and 13
    $sysmonEvents = @()
    
    # Get Process Creation events (ID 1)
    $processEvents = Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-Sysmon/Operational'
        ID=1
        StartTime=$earliestTime
        EndTime=$latestTime
    } -ErrorAction SilentlyContinue | ForEach-Object {
        $eventXml = [xml]$_.ToXml()
        $eventData = $eventXml.Event.EventData.Data
        
        # Extract UtcTime safely
        $utcTimeText = ($eventData | Where-Object {$_.Name -eq "UtcTime"}).'#text'
        $utcTime = $null
        if ($utcTimeText) {
            try {
                $utcTime = [datetime]::Parse($utcTimeText)
            }
            catch {
                $utcTime = $null
            }
        }
        
        [PSCustomObject]@{
            EventType = "ProcessCreation"
            EventID = 1
            TimeCreated = $_.TimeCreated
            UtcTime = $utcTime
            LocalTime = $_.TimeCreated
            ProcessGuid = ($eventData | Where-Object {$_.Name -eq "ProcessGuid"}).'#text'
            ProcessId = ($eventData | Where-Object {$_.Name -eq "ProcessId"}).'#text'
            Image = ($eventData | Where-Object {$_.Name -eq "Image"}).'#text'
            CommandLine = ($eventData | Where-Object {$_.Name -eq "CommandLine"}).'#text'
            User = ($eventData | Where-Object {$_.Name -eq "User"}).'#text'
            ParentImage = ($eventData | Where-Object {$_.Name -eq "ParentImage"}).'#text'
            ParentProcessId = ($eventData | Where-Object {$_.Name -eq "ParentProcessId"}).'#text'
        }
    }
    
    # Get Registry Value Set events (ID 13)
    $registryEvents = Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-Sysmon/Operational'
        ID=13
        StartTime=$earliestTime
        EndTime=$latestTime
    } -ErrorAction SilentlyContinue | ForEach-Object {
        $eventXml = [xml]$_.ToXml()
        $eventData = $eventXml.Event.EventData.Data
        
        # Extract UtcTime safely
        $utcTimeText = ($eventData | Where-Object {$_.Name -eq "UtcTime"}).'#text'
        $utcTime = $null
        if ($utcTimeText) {
            try {
                $utcTime = [datetime]::Parse($utcTimeText)
            }
            catch {
                $utcTime = $null
            }
        }
        
        [PSCustomObject]@{
            EventType = "RegistryValueSet"
            EventID = 13
            TimeCreated = $_.TimeCreated
            UtcTime = $utcTime
            LocalTime = $_.TimeCreated
            ProcessGuid = ($eventData | Where-Object {$_.Name -eq "ProcessGuid"}).'#text'
            ProcessId = ($eventData | Where-Object {$_.Name -eq "ProcessId"}).'#text'
            Image = ($eventData | Where-Object {$_.Name -eq "Image"}).'#text'
            TargetObject = ($eventData | Where-Object {$_.Name -eq "TargetObject"}).'#text'
            Details = ($eventData | Where-Object {$_.Name -eq "Details"}).'#text'
            User = ($eventData | Where-Object {$_.Name -eq "User"}).'#text'
        }
    }
    
    # Combine events
    $sysmonEvents = @($processEvents) + @($registryEvents)
    
    Write-Host "Found $($processEvents.Count) Process Creation events" -ForegroundColor Green
    Write-Host "Found $($registryEvents.Count) Registry Value Set events" -ForegroundColor Green
    Write-Host "Total Sysmon events: $($sysmonEvents.Count)" -ForegroundColor Green
}
catch {
    Write-Error "Failed to load Sysmon events: $_"
    exit 1
}

# ===================================
# Correlation Analysis
# ===================================
Write-Host "`nStarting correlation analysis (±30 second window)..." -ForegroundColor Yellow

$correlationCount = 0
$correlationResults = @()
$textOutput_Content = @()

# Add header
$textOutput_Content += "Discord WebSocket to Sysmon Correlation Analysis"
$textOutput_Content += "=" * 55
$textOutput_Content += "Analysis Date: $(Get-Date)"
$textOutput_Content += "Focus: Process Creation (ID 1) and Registry Value Set (ID 13)"
$textOutput_Content += "IP Filter: Discord Cloudflare ranges + VM IP (10.0.2.4)"
$textOutput_Content += ""

foreach ($alert in $discordAlerts) {
    $alertTime = $alert.ParsedTimestamp
    $windowStart = $alertTime.AddSeconds(-30)
    $windowEnd = $alertTime.AddSeconds(30)
    
    # Find correlated events
    $correlated = $sysmonEvents | Where-Object {
        $eventTime = if ($_.LocalTime) { $_.LocalTime } else { $_.TimeCreated }
        $eventTime -ge $windowStart -and $eventTime -le $windowEnd
    }
    
    if ($correlated -and $correlated.Count -gt 0) {
        $correlationCount++
        
        # Add to text output
        $textOutput_Content += "=== Correlation #${correlationCount} ==="
        $textOutput_Content += "Discord Alert: $alertTime ($($alert.Direction))"
        $textOutput_Content += "Network: $($alert.SourceIP):$($alert.SourcePort) -> $($alert.DestIP):$($alert.DestPort)"
        $textOutput_Content += "Protocol: $($alert.Proto) | Flow: $($alert.FlowId)"
        $textOutput_Content += ""
        
        foreach ($event in $correlated) {
            $eventTime = if ($event.LocalTime) { $event.LocalTime } else { $event.TimeCreated }
            $timeDiff = [math]::Round(($eventTime - $alertTime).TotalSeconds, 2)
            
            # Create correlation record
            $correlationResults += [PSCustomObject]@{
                CorrelationID = $correlationCount
                AlertTime = $alertTime.ToString("yyyy-MM-dd HH:mm:ss.fff")
                AlertDirection = $alert.Direction
                SourceIP = $alert.SourceIP
                SourcePort = $alert.SourcePort
                DestIP = $alert.DestIP
                DestPort = $alert.DestPort
                Protocol = $alert.Proto
                FlowID = $alert.FlowId
                SysmonEventType = $event.EventType
                SysmonEventTime = $eventTime.ToString("yyyy-MM-dd HH:mm:ss.fff")
                TimeDifference_Seconds = $timeDiff
                ProcessImage = $event.Image
                CommandLine = $event.CommandLine
                User = $event.User
                ParentImage = $event.ParentImage
                RegistryKey = $event.TargetObject
                RegistryValue = $event.Details
                ProcessGuid = $event.ProcessGuid
                ProcessID = $event.ProcessId
            }
            
            # Add to text output
            $textOutput_Content += "  $($event.EventType) | $eventTime (${timeDiff}s)"
            
            if ($event.EventType -eq "ProcessCreation") {
                if ($event.Image) { $textOutput_Content += "    Process: $($event.Image)" }
                if ($event.CommandLine) { $textOutput_Content += "    Command: $($event.CommandLine)" }
                if ($event.User) { $textOutput_Content += "    User: $($event.User)" }
                if ($event.ParentImage) { $textOutput_Content += "    Parent: $($event.ParentImage)" }
            }
            elseif ($event.EventType -eq "RegistryValueSet") {
                if ($event.TargetObject) { $textOutput_Content += "    Registry: $($event.TargetObject)" }
                if ($event.Details) { $textOutput_Content += "    Value: $($event.Details)" }
                if ($event.Image) { $textOutput_Content += "    Process: $($event.Image)" }
            }
            $textOutput_Content += ""
        }
    }
}

# ===================================
# Generate Output Files
# ===================================
Write-Host "`nGenerating output files..." -ForegroundColor Yellow

try {
    # CSV Output
    if ($correlationResults.Count -gt 0) {
        $correlationResults | Export-Csv -Path $csvOutput -NoTypeInformation -Encoding UTF8
        Write-Host "CSV saved: $csvOutput" -ForegroundColor Green
    }
    
    # JSON Output
    $jsonOutput_Data = @{
        Metadata = @{
            AnalysisDate = Get-Date
            SuricataLogPath = $eveJsonPath
            CorrelationWindow = "±30 seconds"
            IPRangesMonitored = @("10.0.2.4", "162.159.0.0/16", "104.16.0.0/12")
            SysmonEventsMonitored = @("Process Creation (ID 1)", "Registry Value Set (ID 13)")
            TotalDiscordAlerts = $discordAlerts.Count
            TotalSysmonEvents = $sysmonEvents.Count
            CorrelationsFound = $correlationCount
        }
        Results = $correlationResults
    }
    $jsonOutput_Data | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonOutput -Encoding UTF8
    Write-Host "JSON saved: $jsonOutput" -ForegroundColor Green
    
    # Text Report
    $textOutput_Content += "=" * 55
    $textOutput_Content += "SUMMARY"
    $textOutput_Content += "=" * 55
    
    if ($correlationCount -eq 0) {
        $textOutput_Content += "No correlations found."
    }
    else {
        $textOutput_Content += "Found $correlationCount correlation group(s) with $($correlationResults.Count) total events."
        
        # Analysis
        $processes = $correlationResults | Where-Object { $_.ProcessImage } | Group-Object ProcessImage | Sort-Object Count -Descending
        if ($processes.Count -gt 0) {
            $textOutput_Content += ""
            $textOutput_Content += "Most Active Processes:"
            $processes | Select-Object -First 5 | ForEach-Object {
                $textOutput_Content += "  $($_.Name) - $($_.Count) event(s)"
            }
        }
        
        $registryKeys = $correlationResults | Where-Object { $_.RegistryKey } | Group-Object RegistryKey | Sort-Object Count -Descending
        if ($registryKeys.Count -gt 0) {
            $textOutput_Content += ""
            $textOutput_Content += "Registry Keys Modified:"
            $registryKeys | Select-Object -First 5 | ForEach-Object {
                $textOutput_Content += "  $($_.Name)"
            }
        }
    }
    
    $textOutput_Content += ""
    $textOutput_Content += "Statistics:"
    $textOutput_Content += "  Discord alerts analyzed: $($discordAlerts.Count)"
    $textOutput_Content += "  Sysmon events analyzed: $($sysmonEvents.Count)"
    $textOutput_Content += "  Correlations found: $correlationCount"
    $textOutput_Content += "  Time range: $earliestTime to $latestTime"
    
    $textOutput_Content | Out-File -FilePath $textOutput -Encoding UTF8
    Write-Host "Text report saved: $textOutput" -ForegroundColor Green
    
    # Final summary
    Write-Host "`n=== Analysis Complete ===" -ForegroundColor Magenta
    if ($correlationCount -gt 0) {
        Write-Host "SUCCESS: Found $correlationCount Discord-to-Sysmon correlations!" -ForegroundColor Green
    }
    else {
        Write-Host "No correlations found. Check IP ranges and time windows." -ForegroundColor Yellow
    }
    Write-Host "Files saved to: $outputDir" -ForegroundColor White
}
catch {
    Write-Error "Failed to save output files: $_"
    exit 1
}
