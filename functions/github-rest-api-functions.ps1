function Get-GitHubOrganizationRepositories {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)] [string] $gitHubToken,
        [Parameter(Mandatory = $True)] [string] $gitHubOrganization
    )
    $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($gitHubToken)"))
    $headers = @{'Authorization' = "Basic $base64Token"}
    $page = 0
    do {
        $reposUri = "https://api.github.com/orgs/$gitHubOrganization/repos?page=$page&per_page=100"
        $reposUri = [uri]::EscapeUriString($reposUri)
        $splat = @{
            Method = 'Get' 
            Uri = $reposUri 
            Headers = $headers 
            ContentType = 'application/json'
        }
        [array]$returnRepos = Invoke-RestMethod @splat
        [array]$repositories += $returnRepos
        $page ++
    } until ($returnRepos.Count -lt 100)
    return $repositories
}

function Get-GitHubUserRepositories {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $token,
        [Parameter(Mandatory = $True)] [string] $user
    )

    $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($token)"))
    $headers = @{'Authorization' = "Basic $base64Token"}
    $uri = "https://api.github.com/users/$user/repos"
    $uri = [uri]::EscapeUriString($uri)
    $splat = @{
        Method = 'Get'
        Uri = $uri
        Headers = $headers
        ContentType = 'application/json'
    }
    [array]$returnRepos = Invoke-RestMethod @splat
    return $returnRepos
}

function Get-GitHubRepositoryCommits {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $token,
        [Parameter(Mandatory = $True)] [string] $owner,
        [Parameter(Mandatory = $True)] [string] $repositoryName
    )
    $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($token)"))
    $headers = @{'Authorization' = "Basic $base64Token"}
    $page = 0
    do {
        $uri = "https://api.github.com/repos/$owner/$repositoryName/commits?page=$page&per_page=100"
        $uri = [uri]::EscapeUriString($uri)
        $splat = @{
            Method = 'Get'
            Uri = $uri
            Headers = $headers
            ContentType = 'application/json'
        }
        [array]$return = Invoke-RestMethod @splat
        [array]$commits += $return
        $page ++
    } until ($return.Count -lt 100)
    $commits
}

function New-GitHubIssue {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $gitHubToken,
        [Parameter(Mandatory = $True)] [string] $gitHubRepositoryOwner,
        [Parameter(Mandatory = $True)] [string] $gitHubRepositoryName,
        [Parameter(Mandatory = $True)] [string] $title,
        [Parameter(Mandatory = $True)] [string] $issueContent,
        [Parameter(Mandatory = $False)] [string] $assignee
    )

    $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($gitHubToken)"))
    $headers = @{'Authorization' = "Basic $base64Token"}
    $uri = "https://api.github.com/repos/$gitHubRepositoryOwner/$gitHubRepositoryName/issues"
    $uri = [uri]::EscapeUriString($uri)
    $body = [PSCustomObject]@{
        title = $title
        body = $issueContent
    } 
    
    if ($PSBoundParameters.ContainsKey('assignee')) {
        [array]$assignees = @("$assignee")
        $body | Add-Member -MemberType NoteProperty -Name 'assignees' -Value @("$assignee")
    }
    
    try {
        $splat = @{
            Method = 'Post'
            Uri = $uri
            Headers = $headers
            Body = ([System.Text.Encoding]::UTF8.GetBytes(($body | ConvertTo-Json -Depth 100)))
            ContentType = 'application/json'
        }
        Invoke-RestMethod @splat
    } catch {
        Write-Warning "Unable to create GitHub issue."   
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
    }
}

function Update-GitHubIssue {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $gitHubToken,
        [Parameter(Mandatory = $True)] [string] $gitHubRepositoryOwner,
        [Parameter(Mandatory = $True)] [string] $gitHubRepositoryName,
        [Parameter(Mandatory = $True)] [string] $issueNumber, 
        [Parameter(Mandatory = $True)] [string] $issueContent
    )

    $issueToUpdate = Get-GitHubIssue -gitHubToken $gitHubToken -gitHubRepositoryOwner $gitHubRepositoryOwner -gitHubRepositoryName $gitHubRepositoryName -issueNumber $issueNumber
    $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($gitHubToken)"))
    $headers = @{'Authorization' = "Basic $base64Token"}
    $uri = "https://api.github.com/repos/$gitHubRepositoryOwner/$gitHubRepositoryName/issues/$issueNumber"
    $uri = [uri]::EscapeUriString($uri)
    if ($null -ne $issueToUpdate.assignees.login) {
        $assignees = [array]$issueToUpdate.assignees.login
    } else {
        $assignees = @()
    }
    $body = [PSCustomObject]@{
        title = $issueToUpdate.title
        body = $issueContent
        state = 'open'
        milestone = $issueToUpdate.milestone
        labels = [array]$issueToUpdate.labels.name
        assignees = $assignees
    } 
        
    try {
        $splat = @{
            Method = 'Patch'
            Uri = $uri
            Headers = $headers
            ContentType = 'application/json'
            Body = ([System.Text.Encoding]::UTF8.GetBytes(($body | ConvertTo-Json -Depth 100)))
        }
        Invoke-RestMethod @splat
    } catch {
        Write-Warning "Unable to update GitHub issue."   
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
    }
}

function Get-GitHubIssues {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $gitHubToken,
        [Parameter(Mandatory = $True)] [string] $gitHubRepositoryOwner,
        [Parameter(Mandatory = $True)] [string] $gitHubRepositoryName
    )

    $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($gitHubToken)"))
    $headers = @{'Authorization' = "Basic $base64Token"}
    $page = 0
    do {
        $uri = "https://api.github.com/repos/$gitHubRepositoryOwner/$gitHubRepositoryName/issues?page=$page&per_page=100"
        $uri = [uri]::EscapeUriString($uri)
        $splat = @{
            Method = 'Get'
            Uri = $uri
            Headers = $headers
            ContentType = 'application/json'
        }
        [array]$return = Invoke-RestMethod @splat
        [array]$issues += $return
        $page ++
    } until ($return.Count -lt 100)
    $issues
}

function Get-GitHubIssue {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $gitHubToken,
        [Parameter(Mandatory = $True)] [string] $gitHubRepositoryOwner,
        [Parameter(Mandatory = $True)] [string] $gitHubRepositoryName,
        [Parameter(Mandatory = $True)] [string] $issueNumber
    )

    $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($gitHubToken)"))
    $headers = @{'Authorization' = "Basic $base64Token"}
    $uri = "https://api.github.com/repos/$gitHubRepositoryOwner/$gitHubRepositoryName/issues/$issueNumber"
    $uri = [uri]::EscapeUriString($uri)
    try {
        $splat = @{
            Method = 'Get'
            Uri = $uri
            Headers = $headers
            ContentType = 'application/json'
        }
        Invoke-RestMethod @splat
    } catch {
        Write-Warning "Unable to get GitHub issue."   
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
    }
}

function Get-GitHubUserOrganizations {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $token
    )

    $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($token)"))
    $headers = @{'Authorization' = "Basic $base64Token"}
    $uri = "https://api.github.com/user/orgs"
    $uri = [uri]::EscapeUriString($uri)
    try {
        $splat = @{
            Method = 'Get'
            Uri = $uri
            Headers = $headers
            ContentType = 'application/json'
        }
        Invoke-RestMethod @splat
    } catch {
        Write-Warning "Unable to create GitHub user organizations."   
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
    }
}

function Get-GitHubUser {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $token,
        [Parameter(Mandatory = $True)] [string] $username
    )

    $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($token)"))
    $headers = @{'Authorization' = "Basic $base64Token"}
    $uri = "https://api.github.com/users/$username"
    $uri = [uri]::EscapeUriString($uri)
    try {
        $splat = @{
            Method = 'Get'
            Uri = $uri
            Headers = $headers
            ContentType = 'application/json'
        }
        Invoke-RestMethod @splat
    } catch {
        Write-Warning "Unable to create GitHub user $username."   
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
    }
}

function New-GitHubIssueLabel {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $gitHubToken,
        [Parameter(Mandatory = $True)] [string] $gitHubRepositoryOwner,
        [Parameter(Mandatory = $True)] [string] $gitHubRepositoryName,
        [Parameter(Mandatory = $True)] [string] $issueNumber,
        [Parameter(Mandatory = $False)] [array] $labels
    )

    $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($gitHubToken)"))
    $headers = @{'Authorization' = "Basic $base64Token"}
    $uri = "https://api.github.com/repos/$gitHubRepositoryOwner/$gitHubRepositoryName/issues/$issueNumber/labels"
    $uri = [uri]::EscapeUriString($uri)
    $body = [PSCustomObject]@{
        labels = $labels
    } | ConvertTo-Json -Depth 100 
    try {
        $splat = @{
            Method = 'Post'
            Uri = $uri
            Headers = $headers
            Body = $body
            ContentType = 'application/json'
        }
        Invoke-RestMethod @splat
    } catch {
        Write-Warning "Unable to create GitHub issue label."   
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
    }
}

function Close-GitHubIssue {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $gitHubToken,
        [Parameter(Mandatory = $True)] [string] $gitHubRepositoryOwner,
        [Parameter(Mandatory = $True)] [string] $gitHubRepositoryName,
        [Parameter(Mandatory = $True)] [string] $issueNumber
    )

    $issueToClose = Get-GitHubIssue -gitHubToken $gitHubToken -gitHubRepositoryOwner $gitHubRepositoryOwner -gitHubRepositoryName $gitHubRepositoryName -issueNumber $issueNumber
    $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($gitHubToken)"))
    $headers = @{'Authorization' = "Basic $base64Token"}
    $uri = "https://api.github.com/repos/$gitHubRepositoryOwner/$gitHubRepositoryName/issues/$issueNumber"
    $uri = [uri]::EscapeUriString($uri)
    $body = [PSCustomObject]@{
        title = $issueToClose.title
        body = $issueToClose.body
        state = 'closed'
        milestone = $issueToClose.milestone
        labels = $issueToClose.labels
        assignees = @() # Remove assignees to not have a closed issue assigned to someone
    } 
        
    try {
        $splat = @{
            Method = 'Patch'
            Uri = $uri
            Headers = $headers
            ContentType = 'application/json'
            Body = ([System.Text.Encoding]::UTF8.GetBytes(($body | ConvertTo-Json -Depth 100)))
        }
        Invoke-RestMethod @splat
    } catch {
        Write-Warning "Unable to close GitHub issue."   
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
    }
}

function New-GitHubIssueComment {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $gitHubToken,
        [Parameter(Mandatory = $True)] [string] $gitHubRepositoryOwner,
        [Parameter(Mandatory = $True)] [string] $gitHubRepositoryName,
        [Parameter(Mandatory = $True)] [string] $content,
        [Parameter(Mandatory = $True)] [string] $issueNumber
    )

    $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($gitHubToken)"))
    $headers = @{'Authorization' = "Basic $base64Token"}
    $uri = "https://api.github.com/repos/$gitHubRepositoryOwner/$gitHubRepositoryName/issues/$issueNumber/comments"
    $uri = [uri]::EscapeUriString($uri)
    $body = [PSCustomObject]@{
        body = $content
    } 
        
    try {
        $splat = @{
            Method = 'Post'
            Uri = $uri
            Headers = $headers
            ContentType = 'application/json'
            Body = ([System.Text.Encoding]::UTF8.GetBytes(($body | ConvertTo-Json -Depth 100)))
        }
        Invoke-RestMethod @splat
    } catch {
        Write-Warning "Unable to create GitHub issue comment."   
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
    }
}

function Get-LocalTime($UTCTime) {
    $currentTimeZone = Get-TimeZone | Select-Object -ExpandProperty StandardName
    if ($currentTimeZone -like 'Coordinated Universal Time') {
        $currentTimeZone = 'UTC'
    }
    $timeZone = [System.TimeZoneInfo]::FindSystemTimeZoneById($currentTimeZone)
    [System.TimeZoneInfo]::ConvertTimeFromUtc($UTCTime, $timeZone)
}

function Get-GitHubRateLimit {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $token
    )
    $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($token)"))
    $headers = @{'Authorization' = "Basic $base64Token"}
    $uri = "https://api.github.com/rate_limit"
    $splat = @{
        Method = 'Get'
        Uri = $uri
        Headers = $headers
        ContentType = 'application/json'
    }
    $return = Invoke-RestMethod @splat
    $utcTime = (Get-Date 01.01.1970) + ([System.TimeSpan]::fromseconds($return.rate.reset))
    $localTime = Get-LocalTime -UTCTime $utcTime
    $return.rate | Add-Member -MemberType NoteProperty -Name localTime -Value $localTime
    $return
}

function Get-GitHubRepositoryFileContent {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $gitHubRepository,
        [Parameter(Mandatory = $False)] [string] $path,
        [Parameter(Mandatory = $True)] [string] $branch,
        [Parameter(Mandatory = $False)] [string] $gitHubToken
    )

    if ($PSBoundParameters.ContainsKey('path')) {
        $uri = "https://api.github.com/repos/$gitHubRepository/contents/$path`?ref=$branch" # Need to escape the ? that indicates an http query
    } else {
        $uri = "https://api.github.com/repos/$gitHubRepository/contents`?ref=$branch" # Need to escape the ? that indicates an http query
    }
    
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
    }
}

function Get-GitHubRepositoryCodeScanningAlerts {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)] [string] $gitHubToken,
        [Parameter(Mandatory = $True)] [string] $owner,
        [Parameter(Mandatory = $True)] [string] $repositoryName,
        [Parameter(Mandatory = $False)] [string] $branchName,
        [Parameter(Mandatory = $False)] [string] $pullNumber
    )
    $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($gitHubToken)"))
    $headers = @{'Authorization' = "Basic $base64Token"}
    if ($PSBoundParameters.ContainsKey($branchName)) {
        $baseUri = "https://api.github.com/repos/$owner/$repositoryName/code-scanning/alerts?ref=refs/heads/$branchName"    
    } elseif ($PSBoundParameters.ContainsKey($pullNumber)) {
        $baseUri = "https://api.github.com/repos/$owner/$repositoryName/code-scanning/alerts?refs/pull/$pullNumber/merge"    
    }
    $page = 1
    do {
        $alertsUri = "$baseUri&$page&per_page=100"
        $alertsUri = [uri]::EscapeUriString($alertsUri)
        $splat = @{
            Method = 'Get' 
            Uri = $alertsUri 
            Headers = $headers 
            ContentType = 'application/json'
        }
        [array]$returnAlerts = Invoke-RestMethod @splat
        [array]$allAlerts += $returnAlerts
        $page++
    } until ($returnAlerts.Count -lt 100)
    $allAlerts
}

function Get-GitHubRepositoryTopics {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)] [string] $gitHubToken ,
        [Parameter(Mandatory = $True)] [string] $owner,
        [Parameter(Mandatory = $True)] [string] $repository
    )
    $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($gitHubToken )"))
    $headers = @{
        Authorization = "Basic $base64Token"
        Accept = 'application/vnd.github.mercy-preview+json'
    }
    $topicsUri = "https://api.github.com/repos/$owner/$repository/topics"
    $topicsUri = [uri]::EscapeUriString($topicsUri)
    $splat = @{
        Method = 'Get' 
        Uri = $topicsUri 
        Headers = $headers 
        ContentType = 'application/json'
    }
    [array]$returnTopics = Invoke-RestMethod @splat
    $returnTopics.names
}

function New-GitHubRepositoryTopic {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)] [string] $gitHubToken ,
        [Parameter(Mandatory = $True)] [string] $owner,
        [Parameter(Mandatory = $True)] [string] $repository,
        [Parameter(Mandatory = $True)] [string] $topic
    )
    $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($gitHubToken )"))
    $headers = @{
        Authorization = "Basic $base64Token"
        Accept = 'application/vnd.github.mercy-preview+json'
    }
    [array]$currentTopics = Get-GitHubRepositoryTopics -gitHubToken $gitHubToken -owner $owner -repository $repository
    [array]$topicsToSet = $currentTopics += $topic
    $uri = "https://api.github.com/repos/$owner/$repository/topics"
    $uri = [uri]::EscapeUriString($uri)
    try {
        $splat = @{
            Method = 'Put'
            Uri = $uri
            Headers = $headers
            Body = @{
                names = $topicsToSet
            } | ConvertTo-Json
            ContentType = 'application/json'
        }
        Invoke-RestMethod @splat
    } catch {
        Write-Warning "Unable to add GitHub Topic."   
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
    }
}

function Get-GitHubRepositorySecretScanningAlerts {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)] [string] $gitHubToken ,
        [Parameter(Mandatory = $True)] [string] $owner,
        [Parameter(Mandatory = $True)] [string] $repositoryName
    )
    $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($gitHubToken )"))
    $headers = @{'Authorization' = "Basic $base64Token"}
    $page = 1
    do {
        $alertsUri = "https://api.github.com/repos/$owner/$repositoryName/secret-scanning/alerts?page=$page&per_page=100"
        $alertsUri = [uri]::EscapeUriString($alertsUri)
        $splat = @{
            Method = 'Get' 
            Uri = $alertsUri 
            Headers = $headers 
            ContentType = 'application/json'
        }
        [array]$returnAlerts = Invoke-RestMethod @splat
        [array]$alerts += $returnAlerts
        $page ++
    } until ($returnAlerts.Count -lt 100)
    $alerts
}

function Get-GitHubRepositorySecretScanningStatus {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)] [string] $gitHubToken ,
        [Parameter(Mandatory = $True)] [string] $owner,
        [Parameter(Mandatory = $True)] [string] $repositoryName
    )
    $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($gitHubToken )"))
    $headers = @{'Authorization' = "Basic $base64Token"}
    $alertsUri = "https://api.github.com/repos/$owner/$repositoryName/secret-scanning/alerts"
    $alertsUri = [uri]::EscapeUriString($alertsUri)
    $splat = @{
        Method = 'Get' 
        Uri = $alertsUri 
        Headers = $headers 
        ContentType = 'application/json'
    }
    try {
        $returnAlerts = Invoke-RestMethod @splat
        return 'Enabled'
    } catch {
        if ($_.Exception.Response.StatusCode -like 'NotFound') {
            return 'Disabled'
        } else {
            $ErrorMessage = $_.Exception.Message
            Write-Warning "$ErrorMessage"
        }
    }   
}

function Get-GitHubRepositoryCodeScanningStatus {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)] [string] $gitHubToken,
        [Parameter(Mandatory = $True)] [string] $owner,
        [Parameter(Mandatory = $True)] [string] $repositoryName
    )
    $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($gitHubToken)"))
    $headers = @{'Authorization' = "Basic $base64Token"}
    $alertsUri = "https://api.github.com/repos/$owner/$repositoryName/code-scanning/alerts"
    $alertsUri = [uri]::EscapeUriString($alertsUri)
    try {
        $splat = @{
            Method = 'Get' 
            Uri = $alertsUri 
            Headers = $headers 
            ContentType = 'application/json'
        }
        [array]$returnAlerts = Invoke-RestMethod @splat
        if ($returnAlerts.Count -lt 1) {
            return 'Disabled'
        } elseif ($returnAlerts.Count -gt 0) {
            return 'Enabled'
        }
    } catch {
        if ($_.Exception.Response.StatusCode -like 'NotFound' -or $_.Exception.Response.StatusCode -like 'Forbidden') {
            return 'Disabled'
        } else {
            $ErrorMessage = $_.Exception.Message
            Write-Warning "$ErrorMessage"
        }
    }  
}

function Get-GitHubRepositoryCollaborators {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)] [string] $gitHubToken ,
        [Parameter(Mandatory = $True)] [string] $owner,
        [Parameter(Mandatory = $True)] [string] $repository
    )
    $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($gitHubToken )"))
    $headers = @{Authorization = "Basic $base64Token"}
    $page = 1
    do {
        $collaboratorsUri = "https://api.github.com/repos/$owner/$repository/collaborators?page=$page&per_page=100"
        $collaboratorsUri = [uri]::EscapeUriString($collaboratorsUri)
        $splat = @{
            Method = 'Get' 
            Uri = $collaboratorsUri 
            Headers = $headers 
            ContentType = 'application/json'
        }
        [array]$returnCollaborators = Invoke-RestMethod @splat
        [array]$collaborators += $returnCollaborators
        $page ++
    } until ($returnAlerts.Count -lt 100)
    $collaborators
}

function Get-GitHubOrganizationMembers {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)] [string] $gitHubToken ,
        [Parameter(Mandatory = $True)] [string] $organization
    )
    $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($gitHubToken )"))
    $headers = @{
        Authorization = "Basic $base64Token"
        Accept = 'application/vnd.github.v3+json'}
    $page = 1
    do {
        $membersUri = "https://api.github.com/orgs/$organization/members?page=$page&per_page=100"
        $membersUri = [uri]::EscapeUriString($membersUri)
        $splat = @{
            Method = 'Get' 
            Uri = $membersUri 
            Headers = $headers 
            ContentType = 'application/json'
        }
        [array]$returnMembers = Invoke-RestMethod @splat
        [array]$members += $returnMembers
        $page ++
    } until ($returnMembers.Count -lt 100)
    $members
}

function Get-GitHubOrganizationOwners {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)] [string] $gitHubToken ,
        [Parameter(Mandatory = $True)] [string] $organization
    )
    $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($gitHubToken )"))
    $headers = @{
        Authorization = "Basic $base64Token"
        Accept = 'application/vnd.github.v3+json'}
    $page = 1
    do {
        $ownersUri = "https://api.github.com/orgs/$organization/members?role=admin&page=$page&per_page=100"
        $ownersUri = [uri]::EscapeUriString($ownersUri)
        $splat = @{
            Method = 'Get' 
            Uri = $ownersUri 
            Headers = $headers 
            ContentType = 'application/json'
        }
        [array]$returnOwners = Invoke-RestMethod @splat
        [array]$owners += $returnOwners
        $page ++
    } until ($returnOwners.Count -lt 100)
    $owners
}

function Get-GitHubOrganizationMemberInfo {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)] [string] $gitHubToken,
        [Parameter(Mandatory = $True)] [string] $login,
        [Parameter(Mandatory = $True)] [string] $organizationVerifiedDomainEmails
    )
    $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($gitHubToken )"))
    $headers = @{
        Authorization = "Basic $base64Token"
        Accept = 'application/vnd.github.v3+json'}
    
    $uri = "https://api.github.com/graphql"
    $query = [PSCustomObject]@{
        query = "query {
                    user(login: `"$login`") {
                        login
                        name
                        organizationVerifiedDomainEmails(login: `"$organizationVerifiedDomainEmails`")
                }
        }"
    } | ConvertTo-Json -Depth 100
    
    $splat = @{
        Method = 'Post' 
        Uri = $uri 
        Headers = $headers 
        ContentType = 'application/json'
        Body = $query
    }
    $return = Invoke-RestMethod @splat
    $return.data.user
}

function Get-GitHubRepositoryBranches {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)] [string] $gitHubToken ,
        [Parameter(Mandatory = $True)] [string] $repositoryOwner,
        [Parameter(Mandatory = $True)] [string] $repositoryName
    )
    $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($gitHubToken )"))
    $headers = @{
        Authorization = "Basic $base64Token"
        Accept = 'application/vnd.github.v3+json'}
    $page = 1
    do {
        $branchesUri = "https://api.github.com/repos/$repositoryOwner/$repositoryName/branches?page=$page&per_page=100"
        $branchesUri = [uri]::EscapeUriString($branchesUri)
        $splat = @{
            Method = 'Get' 
            Uri = $branchesUri 
            Headers = $headers 
            ContentType = 'application/json'
        }
        [array]$returnBranches = Invoke-RestMethod @splat
        [array]$branches += $returnBranches
        $page ++
    } until ($returnBranches.Count -lt 100)
    $branches
}

function Get-GitHubOrganizationTeams {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)] [string] $gitHubToken,
        [Parameter(Mandatory = $True)] [string] $organization
    )
    $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($gitHubToken )"))
    $headers = @{
        Authorization = "Basic $base64Token"
        Accept = 'application/vnd.github.v3+json'}
    $page = 1
    do {
        $teamsUri = "https://api.github.com/orgs/$organization/teams?page=$page&per_page=100"
        $teamsUri = [uri]::EscapeUriString($teamsUri)
        $splat = @{
            Method = 'Get' 
            Uri = $teamsUri 
            Headers = $headers 
            ContentType = 'application/json'
        }
        [array]$returnTeams = Invoke-RestMethod @splat
        [array]$teams += $returnTeams
        $page ++
    } until ($returnTeams.Count -lt 100)
    $teams
}

function Set-GitHubRepositoryToArchived {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $gitHubToken,
        [Parameter(Mandatory = $True)] [string] $gitHubRepositoryOwner,
        [Parameter(Mandatory = $True)] [string] $gitHubRepositoryName
    )

    $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($gitHubToken)"))
    $headers = @{'Authorization' = "Basic $base64Token"}
    $uri = "https://api.github.com/repos/$gitHubRepositoryOwner/$gitHubRepositoryName"
    $uri = [uri]::EscapeUriString($uri)
    try {
        $splat = @{
            Method = 'Patch'
            Uri = $uri
            Headers = $headers
            Body = @{
                archived = 'true'
            } | ConvertTo-Json
            ContentType = 'application/json'
        }
        Invoke-RestMethod @splat
    } catch {
        Write-Warning "Unable to archive GitHub repository."   
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
    }
}

function Set-GitHubRepositoryTeamPermission {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $gitHubToken,
        [Parameter(Mandatory = $True)] [string] $gitHubRepositoryOwner,
        [Parameter(Mandatory = $True)] [string] $gitHubRepositoryName,
        [Parameter(Mandatory = $True)] [string] $teamName,
        [Parameter(Mandatory = $False)] [array] [ValidateSet('pull', 'push', 'admin', 'maintain', 'triage')] $permission
    )

    $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($gitHubToken)"))
    $headers = @{'Authorization' = "Basic $base64Token"}
    $teams = Get-GitHubOrganizationTeams -gitHubToken $gitHubToken -organization $gitHubRepositoryOwner
    $team = ($teams | Where-Object {$_.name -like $teamName}).slug
    $uri = "https://api.github.com/orgs/$gitHubRepositoryOwner/teams/$team/repos/$gitHubRepositoryOwner/$gitHubRepositoryName"
    $body = [PSCustomObject]@{
        permission = "$permission"
    } | ConvertTo-Json  
    try {
        $splat = @{
            Method = 'Put'
            Uri = $uri
            Headers = $headers
            Body = $body
            ContentType = 'application/json'
        }
        Invoke-RestMethod @splat
    } catch {
        Write-Warning "Unable to set GitHub Team permissions."   
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
    }
}

function Get-GitHubRepositoryBranchArchive {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $gitHubToken,
        [Parameter(Mandatory = $True)] [string] $gitHubRepositoryName,
        [Parameter(Mandatory = $True)] [string] $gitHubRepositoryOwner,
        [Parameter(Mandatory = $True)] [string] $branch,
        [Parameter(Mandatory = $True)] [string] $outfilePath
    )

    $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($gitHubToken)"))
    $headers = @{'Authorization' = "Basic $base64Token"}
    $uri = "https://api.github.com/repos/$gitHubRepositoryOwner/$gitHubRepositoryName/zipball/$branch"
    $uri = [uri]::EscapeUriString($uri)
    try {
        $splat = @{
            Method = 'Get'
            Uri = $uri
            Headers = $headers
            ContentType = 'application/zip'
            OutFile = "$outfilePath/$($branch.Split([IO.Path]::GetInvalidFileNameChars()) -join '_').zip"
        }
        Invoke-RestMethod @splat
    } catch {
        Write-Warning "Unable to get .ZIP archive of repository $gitHubRepositoryName."   
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
    }
}

function New-GitHubRepositoryBackup {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $gitHubToken,
        [Parameter(Mandatory = $True)] [string] $gitHubRepositoryName,
        [Parameter(Mandatory = $True)] [string] $gitHubRepositoryOwner,
        [Parameter(Mandatory = $True)] [string] $outfilePath
    )

    $splat = @{
        gitHubToken = $gitHubToken
        repositoryName = $gitHubRepositoryName
        repositoryOwner = $gitHubRepositoryOwner
    }
    [array]$branches = Get-GitHubRepositoryBranches @splat
    foreach ($branch in $branches) {
        $splat = @{
            gitHubToken = $gitHubToken
            gitHubRepositoryName = $gitHubRepositoryName
            gitHubRepositoryOwner = $gitHubRepositoryOwner
            branch = $branch.name
            outFile = $outfilePath
        }
        Get-GitHubRepositoryBranchArchive @splat 
    }
}

function Remove-GitHubRepository {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $gitHubToken,
        [Parameter(Mandatory = $True)] [string] $gitHubRepositoryOwner,
        [Parameter(Mandatory = $True)] [string] $gitHubRepositoryName
    )

    $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($gitHubToken)"))
    $headers = @{'Authorization' = "Basic $base64Token"}
    $uri = "https://api.github.com/repos/$gitHubRepositoryOwner/$gitHubRepositoryName"
    $uri = [uri]::EscapeUriString($uri)
    try {
        $splat = @{
            Method = 'Delete'
            Uri = $uri
            Headers = $headers
            ContentType = 'application/json'
        }
        Invoke-RestMethod @splat
    } catch {
        Write-Warning "Unable to remove GitHub repository."   
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
    }
}

function Get-GitHubPullRequest {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)] [string] $gitHubToken ,
        [Parameter(Mandatory = $True)] [string] $repositoryOwner,
        [Parameter(Mandatory = $True)] [string] $repositoryName,
        [Parameter(Mandatory = $True)] [string] $pullNumber
    )
    $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($gitHubToken )"))
    $headers = @{
        Authorization = "Basic $base64Token"
        Accept = 'application/vnd.github.v3+json'
    }

    $pullsUri = "https://api.github.com/repos/$repositoryOwner/$repositoryName/pulls/$pullNumber"
    $pullsUri = [uri]::EscapeUriString($pullsUri)
    $splat = @{
        Method = 'Get' 
        Uri = $pullsUri 
        Headers = $headers 
        ContentType = 'application/json'
    }
    Invoke-RestMethod @splat
}
