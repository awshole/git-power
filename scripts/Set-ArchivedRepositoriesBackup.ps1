[CmdletBinding()]
Param
(
    [Parameter(Mandatory = $True)] [string] $gitHubToken,
    [Parameter(Mandatory = $True)] [string] $gitHubOrganization,
    [Parameter(Mandatory = $True)] [string] $storageAccountName,
    [Parameter(Mandatory = $True)] [ValidateSet("All", "ArchivedOnly")] [string] $backupSet,
    [Parameter(Mandatory = $False)] [switch] $deleteOnBackup,
    [Parameter(Mandatory = $False)] [switch] $Force
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
    if ($PSBoundParameters.ContainsKey('gitHubtoken')) {
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

$dotSourceFilePath = 'functions/github-rest-api-functions.ps1'
$splat = @{
    gitHubToken = $gitHubToken
    gitHubRepository = 'awshole/git-power'
    path = $dotSourceFilePath
    branch = 'main'
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

$date = Get-Date -Format yyyy-MM-dd_hh-mm-ss
Write-OutPut "Getting GitHub repositories."
[array]$gitHubRepositories = Get-GitHubOrganizationRepositories -gitHubToken $gitHubToken -gitHubOrganization $gitHubOrganization
if ($backupSet -like "ArchivedOnly") {
    $gitHubRepositories = $gitHubRepositories | Where-Object {$_.archived -eq $True}
    Write-OutPut "Got $($gitHubRepositories.Count) archived GitHub repositories."
    $backupDirectory = New-Item -Path "$gitHubOrganization-archived-github-repositories-$date" -ItemType Directory
}
Write-OutPut "Got $($gitHubRepositories.Count) GitHub repositories."
$backupDirectory = New-Item -Path "$gitHubOrganization-github-repositories-$date" -ItemType Directory
$storageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName (Get-AzStorageAccount | Where-Object {$_.StorageAccountName -like $storageAccountName}).ResourceGroupName -Name $storageAccountName)[0].Value
$context = New-AzStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $storageAccountKey
foreach ($repository in $gitHubRepositories) {
    Write-Progress -Id 1 -Activity "Obtaining .ZIP files" -PercentComplete (($gitHubRepositories.IndexOf($repository) / $gitHubRepositories.Count) * 100) 
    $rateLimit = Get-GitHubRateLimit -token $gitHubToken
    if ($rateLimit.rate.remaining -lt 50) {
        $timeSpan = New-TimeSpan -Start (Get-Date) -End $rateLimit.rate.localTime
        $secondsToWait = $timeSpan.TotalSeconds
        Write-OutPut "Waiting for $($timeSpan.minutes) minutes for API rate limit to reset."
        Start-Sleep -seconds $secondsToWait
    }
    $repoBackupDirectory = New-Item -Path "$($backupDirectory.FullName)/$($repository.Name)" -ItemType Directory
    $splat = @{
        gitHubToken = $gitHubToken
        gitHubRepositoryOwner = $repository.owner.login
        gitHubRepositoryName = $repository.Name
        outfilePath = "$backupDirectory/$($repository.Name)"
    }
    New-GitHubRepositoryBackup @splat
    [array]$itemsToUpload = Get-ChildItem -Path $repoBackupDirectory.FullName
    foreach ($item in $itemsToUpload) {
        Write-Progress -Id 2 -ParentId 1 -Activity "Uploading files" -PercentComplete (($gitHubRepositories.IndexOf($repository) / $gitHubRepositories.Count) * 100)
        try {
            $splat = @{
                Context = $context
                FileSystem = 'archived-repositories'
                Path = "$($repository.Name)/$date/$($item.Name)"
                Source = $item.FullName
                Force = $true
            }
            New-AzDataLakeGen2Item @splat | Out-Null
            $okayToRemove = $True
        } catch {
            Write-Warning "Was not able to create backup for repository $($repository.name)."
            $okayToRemove = $False
        }         
    }
    Write-Progress -Id 2 -ParentId 1 -Activity "Uploading files" -Completed
    Remove-Item -Path $repoBackupDirectory.FullName -Recurse -Force
    if ($okayToRemove -eq $True) {
        if ($deleteOnBackup -eq $true -and $backupSet -like "ArchivedOnly") {
            Remove-GitHubRepository -gitHubToken $gitHubToken -gitHubRepositoryOwner $repository.full_name.Split('/')[0] -gitHubRepositoryName $repository.name
        } elseif ($deleteOnBackup -eq $true -and $backupSet -like "All" -and $Force -eq $true) {
            Remove-GitHubRepository -gitHubToken $gitHubToken -gitHubRepositoryOwner $repository.full_name.Split('/')[0] -gitHubRepositoryName $repository.name
        } elseif ($deleteOnBackup -eq $true -and $backupSet -like "All" -and $Force -eq $false) {
            Write-Warning "The 'Force' parameter switch was not included. Include the 'Force' parameter switch to remove $($repository.name)."
        }
    } else {
        Write-Warning "Will not attempt to remove repository regardless of parameter specification."
    }   
}

Write-Progress -Id 1 -Activity "Obtaining .ZIP files" -Completed
Remove-Item -Path $backupDirectory.FullName -Recurse -Force
