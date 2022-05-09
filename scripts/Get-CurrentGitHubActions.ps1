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

# Dot source GitHub function library
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

Write-OutPut "Getting GitHub repositories."
[array]$gitHubRepositories = Get-GitHubOrganizationRepositories -gitHubToken $gitHubToken -gitHubOrganization $gitHubOrganization | Where-Object {$_.archived -eq $False}
Write-OutPut "Got $($gitHubRepositories.Count) GitHub repositories."
foreach ($repository in $gitHubRepositories) {
    $repositoryBranches = Get-GitHubRepositoryBranches -gitHubToken $gitHubToken -repositoryOwner $repository.owner.login -repositoryName $repository.name
    foreach ($branch in $repositoryBranches) {
        $splat = @{
            gitHubToken = $gitHubToken
            gitHubRepository = $repository.full_name
            path = '.github/workflows'
            branch = $branch.name
        }
        [array]$workflowDirectory = Get-GitHubRepositoryFileContent @splat -WarningAction Ignore
        if ($workflowDirectory.Count -gt 0) {
            foreach ($workflow in $workflowDirectory) {
                $actions = $null
                $splat = @{
                    gitHubToken = $gitHubToken
                    gitHubRepository = $repository.full_name
                    path = $workflow.path
                    branch = $branch.name
                }
                $workflowContent = Get-GitHubRepositoryFileContent @splat
                [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($workflowContent.content)) | Out-File -FilePath $workflow.name -Force
                [array]$actions += Get-Content -Path $workflow.name | Where-Object {$_ -like "*uses:*"} | ForEach-Object {$_.Split(':')[-1].Trim()} | Select-Object -Unique
                Remove-Item -Path $workflow.name -Force
                $actions | ForEach-Object {[array]$allActions += [PSCustomObject]@{
                        'Action Name' = $_
                        'Repository' = $repository.name
                        'Branch' = $branch.name
                        'Workflow' = $workflow.name
                    }
                }
            }
        }
    }
}

Write-OutPut "Uploading to storage account."
$date = Get-Date -Format yyyy-MM-dd_hh-mm-ss
$localFileName = "$gitHubOrganization-github-actions-$date.json"
$localFilePath = "$env:TMP\$localFileName"
$destinationFileName = $localFileName.Replace('.json', '.zip')
$destinationFilePath = "$env:TMP\$destinationFileName"
$allActions | ConvertTo-Json -Depth 100 | Out-File -FilePath $localFilePath -Force 
Get-Item -Path $localFilePath | Compress-Archive -DestinationPath $destinationFilePath -Force
$storageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName (Get-AzStorageAccount | Where-Object {$_.StorageAccountName -like $storageAccountName}).ResourceGroupName -Name $storageAccountName)[0].Value
$context = New-AzStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $storageAccountKey
New-AzDataLakeGen2Item -Context $context -FileSystem 'github-actions' -Path $destinationFileName -Source $destinationFilePath -Force | Out-Null
Write-OutPut "Uploaded to storage account." 
