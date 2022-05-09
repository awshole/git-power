<#
.SYNOPSIS 
    This script is to be run as part of a set of GitHub Action steps. It creates
    a GitHub Issue for issues identified by a CodeQL scan (prior step in GitHub 
    Action workflow). If a GitHub Issue currently exists for issues identified 
    by CodeQL, that issue will be closed in order to keep only one active open 
    issue. Additionally, that issue will have a comment that references the issue 
    that this script creates. 

    .DESCRIPTION
    This script requires 6 parameters (dotSourceFileRepository, dotSourceFileBranch,
    dotSourceFilePath, gitHubToken, gitHubRepository, gitHubRepositoryBranchName) and 2
    optional parameters (githubIssueAssignee, labels) to post a GitHub Issue with a 
    summary of the CodeQL scan. 

    .PARAMETER dotSourceFileRepository
    This parameter expects a string value corresponding to the name of the repository
    that contains the file mentioned in the dotSourceFilePath parameter. For example,
    awshole/git-power.
    
    .PARAMETER dotSourceFileBranch
    This parameter expects a string value corresponding to the name of the branch that 
    the file mentioned in the dotSourceFilePath parameter exists in (e.g., main).

    .PARAMETER dotSourceFilePath
    This parameter expects a string value corresponding to the full GitHub path to 
    the github-rest-api-functions.ps1 file. For example functions/github-rest-api-functions.

    .PARAMETER gitHubToken
    This parameter expects a string value corresponding to the API token to use when 
    accessing the GitHub organization.

    .PARAMETER gitHubRepository
    This parameter expects a string value corresponding to the full name of the GitHub
    repository (i.e., including the owner) to gather CodeQL code scanning alerts from. 
    For example, awshole/snyk-demo. 

    .PARAMETER gitHubRepositoryBranchName
    This parameter expects a string value corresponding to the branch name to retrive
    CodeQL code scanning alerts for.

    .PARAMETER githubIssueAssignee
    This is an optional parameter that expects a GitHub username that should be assigned to
    the issues that may be created.   

    .PARAMETER labels
    This is an optional parameter that expects an array of strings that are labels that will
    be attached to the issue.
    
    .OUTPUTS
    Text is output to the screen to display progress, and GitHub Issues are created. No
    native PowerShell objects are returned.

    .EXAMPLE
    $splat = @{
        dotSourceFileRepository = 'awshole/git-power'
        dotSourceFileBranch = 'main'
        dotSourceFilePath = 'functions/github-rest-api-functions.ps1'
        gitHubToken = <omitted>
        gitHubRepository = 'awshole/snyk-demo'
        gitHubRepositoryBranchName = 'main'
        gitHubIssueAssignee = 'awshole'
        labels = @('security', 'code-ql')
    }
    .\Set-CodeQLGitHubIssue.ps1 @splat

    .NOTES
    Author                  : David Wiggs - dwiggs4@gmail.com
#>

[CmdletBinding()]
Param
(
    [Parameter(Mandatory = $True)] [string] $dotSourceFileRepository,    
    [Parameter(Mandatory = $True)] [string] $dotSourceFileBranch,
    [Parameter(Mandatory = $True)] [string] $dotSourceFilePath,
    [Parameter(Mandatory = $True)] [string] $gitHubToken,
    [Parameter(Mandatory = $True)] [string] $gitHubRepository,
    [Parameter(Mandatory = $True)] [string] $gitHubRepositoryBranchName,
    [Parameter(Mandatory = $False)] [string] $gitHubIssueAssignee,
    [Parameter(Mandatory = $False)] [array] $labels,
    [Parameter(Mandatory = $False)] [string] $runId
)

function Get-GitHubRepositoryFileContent {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $gitHubRepository,
        [Parameter(Mandatory = $True)] [string] $path,
        [Parameter(Mandatory = $True)] [string] $branch,
        [Parameter(Mandatory = $False)] [string] $gitHubToken
    )

    $uri = "https://api.github.com/repos/$gitHubRepository/contents/$path`?ref=$branch" # Need to escape the ? that indicates an http query
    $uri = [uri]::EscapeUriString($uri)
    if ($PSBoundParameters.ContainsKey('gitHubToken')) {
        $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($gitHubToken)"))
        $headers = @{'Authorization' = "Basic $base64Token"}
        $splat = @{
            Method = 'Get'
            Uri = $uri
            Headers = $headers
            ContentType = 'application/json'
        }
    } else {
        $splat = @{
            Method = 'Get'
            Uri = $uri
            ContentType = 'application/json'
        }
    } 
    
    try {
        Invoke-RestMethod @splat
    } catch {
        Write-Warning "Unable to get file content."   
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
        break
    }
}

$gitHubRepositoryOwner = $gitHubRepository.Split('/')[0]
$gitHubRepositoryName = $gitHubRepository.Split('/')[-1]
# Dot source GitHub function library
$splat = @{
    gitHubToken = $gitHubToken
    gitHubRepository = $dotSourceFileRepository
    path = $dotSourceFilePath
    branch = $dotSourceFileBranch
}
$dotSourceFileData = Get-GitHubRepositoryFileContent @splat
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($dotSourceFileData.content)) | Out-File -FilePath $dotSourceFilePath.Split('/')[-1] -Force
$dotSourceFile = Get-Item -Path $dotSourceFilePath.Split('/')[-1]
if (Test-Path -Path $dotSourceFilePath.Split('/')[-1]) {
    try {
        . $dotSourceFile.FullName
        Remove-Item -Path $dotSourceFilePath.Split('/')[-1] -Recurse -Force
    } catch {
        Write-Warning "Unable to dot source file: $dotSourceFilePath."
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
        break
    }
} else {
    Write-Warning "Could not find path to file: $dotSourceFilePath."
    $ErrorMessage = $_.Exception.Message
    Write-Warning "$ErrorMessage"
    break
}

$splat = @{
    gitHubToken = $gitHubToken
    owner = $gitHubRepositoryOwner
    repositoryName = $gitHubRepositoryName
    branchName = $gitHubRepositoryBranchName
}
[array]$codeScanningIssues = Get-GitHubRepositoryCodeScanningAlerts @splat | Where-Object {$_.state -like 'open'}
if ($codeScanningIssues.Count -gt 0) {
    [array]$codeQLIssues = $codeScanningIssues | Where-Object {$_.tool.name -like 'CodeQL' -and $_.state -like 'open'} | Select-Object -Property rule -ExpandProperty most_recent_instance
    [array]$uniqueCodeQLIssueDescriptions = $codeQLIssues.rule | Select-Object -Property severity, description -Unique
    $severityMapping = @{
        error = 'High'
        warning = 'Medium'
        note = 'Low'
    }
    foreach ($uniqueCodeQLIssueDescription in $uniqueCodeQLIssueDescriptions) {
        [array]$occurrences = $codeQLIssues | Where-Object {$_.rule.description -like $uniqueCodeQLIssueDescription.description}
        [array]$issueData += [PSCustomObject][ordered]@{
            Issue = $uniqueCodeQLIssueDescription.description
            Severity = $severityMapping."$($uniqueCodeQLIssueDescription.severity)"
            Occurrences = $occurrences.Count
        }
    }

    $issueData | ForEach-Object {
        if ($_.Severity -like 'High') {$_ | Add-Member -MemberType NoteProperty -Name NumericalSeverity -Value 1}
        elseif ($_.Severity -like 'Medium') {$_ | Add-Member -MemberType NoteProperty -Name NumericalSeverity -Value 2}
        elseif ($_.Severity -like 'Low') {$_ | Add-Member -MemberType NoteProperty -Name NumericalSeverity -Value 3}
    }

    $issueData = $issueData | Sort-Object -Property NumericalSeverity 
    Add-Type -AssemblyName System.Web
    $table = [System.Web.HttpUtility]::HtmlDecode(($issueData | Select-Object -Property Issue, Severity, Occurrences | ConvertTo-Html -Fragment))

    $issueContent = "## Overview 

CodeQL is the analysis engine used by developers to automate security checks, and by security researchers to perform variant analysis. In CodeQL, code is treated like data. Security vulnerabilities, bugs, and other errors are modeled as queries that can be executed against databases extracted from code. To learn more about CodeQL, [see the documentation](https://codeql.github.com/docs/).

## Summary of results

The following issues were identified. See additional details (including guidance on fixing issues) on the [Security tab](https://github.com/$gitHubRepository/security/code-scanning?query=tool%3ACodeQL+ref%3Arefs%2Fheads%2F$gitHubRepositoryBranchName) of this repository.

$table"

    # Determine if there is a current GitHub issue for CodeQL
    Write-Output "Getting current GitHub Issues."
    $splat = @{
        gitHubToken = $gitHubToken
        gitHubRepositoryOwner = $gitHubRepositoryOwner
        gitHubRepositoryName = $gitHubRepositoryName
    }
    $currentGitHubIssues = Get-GitHubIssues @splat 
    $title = "[CodeQL] Scan results ($gitHubRepositoryBranchName)"
    if ($currentGitHubIssues.title -contains $title) {
        $currentGitHubIssue = $currentGitHubIssues | Where-Object {$_.title -eq $title -and $_.state -like 'open'}
        Write-Output "Updating GitHub Issue."
        $splat = @{
            gitHubToken = $gitHubToken 
            gitHubRepositoryOwner = $gitHubRepositoryOwner 
            gitHubRepositoryName = $gitHubRepositoryName 
            issueContent = "$issueContent" 
            issueNumber = $currentGitHubIssue.number
        }
        $issue = Update-GitHubIssue @splat | Out-Null
        if ($null -ne $runId) {
            $content = "A [subsequent scan](https://github.com/$gitHubRepositoryOwner/$gitHubRepositoryName/actions/runs/$runId) was executed."
            Write-Output "Commenting on issue."
            $splat = @{
                gitHubToken = $gitHubToken 
                gitHubRepositoryOwner = $gitHubRepositoryOwner 
                gitHubRepositoryName = $gitHubRepositoryName
                issueNumber = $currentGitHubIssue.number
                content = $content
            }
            New-GitHubIssueComment @splat | Out-Null
        }
    } else {
        Write-Output "Creating GitHub Issue."
        $splat = @{
            gitHubToken = $gitHubToken 
            gitHubRepositoryOwner = $gitHubRepositoryOwner 
            gitHubRepositoryName = $gitHubRepositoryName 
            title = "$title" 
            issueContent = "$issueContent" 
        }
        if ($PSBoundParameters.ContainsKey('githubIssueAssignee')) {
            $splat.Add('assignee', "$githubIssueAssignee")
        }
        $issue = New-GitHubIssue @splat
        if ($PSBoundParameters.ContainsKey('labels')) {
            Write-Output "Adding labels to GitHub Issue."
            $splat = @{
                gitHubToken = $gitHubToken 
                gitHubRepositoryOwner = $gitHubRepositoryOwner 
                gitHubRepositoryName = $gitHubRepositoryName
                issueNumber = $issue.number 
                labels = $labels
            }
            New-GitHubIssueLabel @splat | Out-Null
        }
    } 
}
