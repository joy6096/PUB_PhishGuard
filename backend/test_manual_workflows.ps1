
$ErrorActionPreference = "Stop"

$BaseUrl = "http://localhost:8000"
$Results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param(
        [string]$Name,
        [bool]$Passed,
        [string]$Details
    )

    $status = if ($Passed) { "PASS" } else { "FAIL" }

    $Results.Add([PSCustomObject]@{
        Test   = $Name
        Status = $status
        Details = $Details
    })

    if ($Passed) {
        Write-Host "[PASS] $Name - $Details" -ForegroundColor Green
    }
    else {
        Write-Host "[FAIL] $Name - $Details" -ForegroundColor Red
    }
}

function Invoke-ApiTest {
    param(
        [string]$Name,
        [string]$Method,
        [string]$Path,
        [object]$Body,
        [int]$ExpectedStatus = 200
    )

    try {
        $params = @{
            Uri         = "$BaseUrl$Path"
            Method      = $Method
            ErrorAction = "Stop"
        }

        if ($null -ne $Body) {
            $params["ContentType"] = "application/json"
            $params["Body"] = $Body | ConvertTo-Json -Depth 10
        }

        $response = Invoke-RestMethod @params

        if ($ExpectedStatus -eq 200) {
            Add-Result $Name $true "HTTP 200; API returned a response"
            return $response
        }

        Add-Result $Name $false "Expected HTTP $ExpectedStatus but received HTTP 200"
        return $null
    }
    catch {
        $statusCode = $null

        if ($_.Exception.Response) {
            try {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }
            catch {
                $statusCode = $null
            }
        }

        if ($null -ne $statusCode -and $statusCode -eq $ExpectedStatus) {
            Add-Result $Name $true "Received expected HTTP $statusCode"
        }
        else {
            $actual = if ($null -ne $statusCode) {
                "HTTP $statusCode"
            }
            else {
                $_.Exception.Message
            }

            Add-Result $Name $false "Expected HTTP $ExpectedStatus; received $actual"
        }

        return $null
    }
}

Write-Host "`n======================================" -ForegroundColor Cyan
Write-Host " PUB PhishGuard Manual API Test" -ForegroundColor Cyan
Write-Host "======================================`n" -ForegroundColor Cyan

# --------------------------------------------------
# 1. Check backend health
# --------------------------------------------------

try {
    $health = Invoke-RestMethod -Uri "$BaseUrl/health" -Method Get

    Add-Result "Backend health" $true (
        "Backend is reachable: " + ($health | ConvertTo-Json -Compress)
    )
}
catch {
    Add-Result "Backend health" $false $_.Exception.Message

    Write-Host "`nBackend is not reachable." -ForegroundColor Red
    Write-Host "Start it with: uvicorn app.main:app --reload" -ForegroundColor Yellow
    return
}

# --------------------------------------------------
# 2. URL scan
# --------------------------------------------------

$urlResult = Invoke-ApiTest `
    -Name "URL scan API" `
    -Method Post `
    -Path "/api/v1/scans/url" `
    -Body @{
        url = "https://secure-login-example.com/verify-account"
    }

if ($null -ne $urlResult) {
    $score = $urlResult.risk_score
    $verdict = $urlResult.verdict
    $indicators = $urlResult.indicators

    $hasScore = $null -ne $score -and [int]$score -ge 0 -and [int]$score -le 100
    $hasVerdict = -not [string]::IsNullOrWhiteSpace([string]$verdict)
    $hasIndicators = $null -ne $indicators

    Add-Result "URL risk score" $hasScore "Score: $score / 100"
    Add-Result "URL verdict" $hasVerdict "Verdict: $verdict"
    Add-Result "URL indicators field" $hasIndicators "Indicators field is present"

    Write-Host "`nURL report:" -ForegroundColor Cyan
    $urlResult | ConvertTo-Json -Depth 10
}

# --------------------------------------------------
# 3. SMS / chat message scan
# --------------------------------------------------

$messageResult = Invoke-ApiTest `
    -Name "Message scan API" `
    -Method Post `
    -Path "/api/v1/scans/message" `
    -Body @{
        text = "Urgent! Your account will be blocked. Verify your password and OTP immediately."
        language_hint = "en"
    }

if ($null -ne $messageResult) {
    $validScore = $null -ne $messageResult.risk_score `
        -and [int]$messageResult.risk_score -ge 0 `
        -and [int]$messageResult.risk_score -le 100

    Add-Result "Message risk score" $validScore (
        "Score: $($messageResult.risk_score) / 100"
    )

    Add-Result "Message indicators" (
        $null -ne $messageResult.indicators
    ) "Indicators field is present"

    Write-Host "`nMessage report:" -ForegroundColor Cyan
    $messageResult | ConvertTo-Json -Depth 10
}

# --------------------------------------------------
# 4. Pasted email scan
# --------------------------------------------------

$emailText = @"
From: Security Team <security@example.com>
To: student@example.com
Reply-To: unknown@example.net
Subject: Urgent - Verify your account
Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail

Your account will be suspended. Verify your password and credentials immediately.
"@

$emailResult = Invoke-ApiTest `
    -Name "Pasted email scan API" `
    -Method Post `
    -Path "/api/v1/scans/email" `
    -Body @{
        email_text = $emailText
    }

if ($null -ne $emailResult) {
    $validScore = $null -ne $emailResult.risk_score `
        -and [int]$emailResult.risk_score -ge 0 `
        -and [int]$emailResult.risk_score -le 100

    Add-Result "Email risk score" $validScore (
        "Score: $($emailResult.risk_score) / 100"
    )

    Add-Result "Email indicators" (
        $null -ne $emailResult.indicators
    ) "Indicators field is present"

    Write-Host "`nEmail report:" -ForegroundColor Cyan
    $emailResult | ConvertTo-Json -Depth 10
}

# --------------------------------------------------
# 5. Create a temporary valid EML file and upload it
# --------------------------------------------------

$tempDirectory = Join-Path $env:TEMP "PhishGuardManualTest"
New-Item -ItemType Directory -Path $tempDirectory -Force | Out-Null

$validEmlPath = Join-Path $tempDirectory "sample_phishing.eml"
$wrongExtensionPath = Join-Path $tempDirectory "wrong_extension.txt"
$emptyEmlPath = Join-Path $tempDirectory "empty.eml"

$emlContent = @"
From: Security Team <security@example.com>
To: student@example.com
Reply-To: unknown@example.net
Subject: Urgent - Verify your account
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Urgent! Your account will be suspended.
Verify your password and credentials immediately.
"@

# Write email as UTF-8 without BOM, using CRLF line endings.
$emlContent = $emlContent -replace "`r?`n", "`r`n"
[System.IO.File]::WriteAllText(
    $validEmlPath,
    $emlContent,
    [System.Text.UTF8Encoding]::new($false)
)

[System.IO.File]::WriteAllText(
    $wrongExtensionPath,
    $emlContent,
    [System.Text.UTF8Encoding]::new($false)
)

[System.IO.File]::WriteAllBytes($emptyEmlPath, [byte[]]@())

try {
    $uploadResponse = Invoke-RestMethod `
        -Uri "$BaseUrl/api/v1/scans/email/eml" `
        -Method Post `
        -Form @{
            file = Get-Item $validEmlPath
        }

    $validUpload = $null -ne $uploadResponse.risk_score `
        -and $null -ne $uploadResponse.email_metadata

    Add-Result "Valid EML upload" $validUpload (
        "Score: $($uploadResponse.risk_score); metadata returned"
    )

    Write-Host "`nEML report:" -ForegroundColor Cyan
    $uploadResponse | ConvertTo-Json -Depth 10
}
catch {
    Add-Result "Valid EML upload" $false $_.Exception.Message
}

# --------------------------------------------------
# 6. Wrong extension must be rejected
# --------------------------------------------------

try {
    $wrongResponse = Invoke-RestMethod `
        -Uri "$BaseUrl/api/v1/scans/email/eml" `
        -Method Post `
        -Form @{
            file = Get-Item $wrongExtensionPath
        }

    Add-Result "Wrong extension rejection" $false (
        "Expected HTTP 400; request was accepted"
    )
}
catch {
    $statusCode = $null

    if ($_.Exception.Response) {
        try {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        catch {}
    }

    Add-Result "Wrong extension rejection" (
        $statusCode -eq 400
    ) "Expected HTTP 400; received $statusCode"
}

# --------------------------------------------------
# 7. Empty EML must be rejected
# --------------------------------------------------

try {
    $emptyResponse = Invoke-RestMethod `
        -Uri "$BaseUrl/api/v1/scans/email/eml" `
        -Method Post `
        -Form @{
            file = Get-Item $emptyEmlPath
        }

    Add-Result "Empty EML rejection" $false (
        "Expected HTTP 400; request was accepted"
    )
}
catch {
    $statusCode = $null

    if ($_.Exception.Response) {
        try {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        catch {}
    }

    Add-Result "Empty EML rejection" (
        $statusCode -eq 400
    ) "Expected HTTP 400; received $statusCode"
}

# --------------------------------------------------
# Final summary
# --------------------------------------------------

Write-Host "`n======================================" -ForegroundColor Cyan
Write-Host " FINAL TEST SUMMARY" -ForegroundColor Cyan
Write-Host "======================================`n" -ForegroundColor Cyan

$Results | Format-Table -AutoSize

$passedCount = @($Results | Where-Object Status -eq "PASS").Count
$failedCount = @($Results | Where-Object Status -eq "FAIL").Count

Write-Host "Passed: $passedCount" -ForegroundColor Green
Write-Host "Failed: $failedCount" -ForegroundColor $(if ($failedCount -gt 0) { "Red" } else { "Green" })

Write-Host "`nTemporary test files: $tempDirectory"

if ($failedCount -gt 0) {
    exit 1
}

Write-Host "`nAll manual API checks passed!" -ForegroundColor Green
