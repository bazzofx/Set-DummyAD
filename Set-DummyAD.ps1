# ==========================
# ACME AD Bootstrap (idempotent)
# ==========================

# --- Static variables ---
$modelPath    = ".\model.json"
$usersCSVPath = ".\names.csv"

# --- Helpers ---
function Ensure-OU {
    param(
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [string]$Path,
        [bool]$Protect = $false
    )
    $existing = Get-ADOrganizationalUnit -Filter 'Name -eq $Name' -SearchBase $Path -SearchScope OneLevel -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-ADOrganizationalUnit -Name $Name -Path $Path -ProtectedFromAccidentalDeletion:$Protect -ErrorAction Stop | Out-Null
    }
    return (Get-ADOrganizationalUnit -Filter 'Name -eq $Name' -SearchBase $Path -SearchScope OneLevel).DistinguishedName
}

function Ensure-Group {
    param(
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [ValidateSet('Security')] $Category,
        [Parameter(Mandatory)] [ValidateSet('Global','DomainLocal','Universal')] $Scope
    )
    $g = Get-ADGroup -LDAPFilter "(cn=$([regex]::Escape($Name)))" -SearchBase $Path -ErrorAction SilentlyContinue
    if (-not $g) {
        New-ADGroup -Name $Name -GroupCategory $Category -GroupScope $Scope -Path $Path -ErrorAction Stop | Out-Null
    }
}

function Ensure-GroupMember {
    param(
        [Parameter(Mandatory)] [string]$Group,
        [Parameter(Mandatory)] [string]$Member
    )
    $has = Get-ADGroupMember -Identity $Group -Recursive -ErrorAction SilentlyContinue | Where-Object { $_.SamAccountName -eq $Member }
    if (-not $has) {
        Add-ADGroupMember -Identity $Group -Members $Member -ErrorAction Stop
    }
}

function Get-UniqueSamUpn {
    param(
        [Parameter(Mandatory)] [string]$BaseSam,
        [Parameter(Mandatory)] [string]$Domain
    )
    $sam = $BaseSam
    $upn = "$sam@$Domain"
    $i = 1
    while (Get-ADUser -Filter 'SamAccountName -eq $sam' -ErrorAction SilentlyContinue) {
        $sam = "$BaseSam$i"
        $upn = "$sam@$Domain"
        $i++
    }
    return @{ Sam=$sam; Upn=$upn }
}

# --- [1] Read files ---
if ((Test-Path $modelPath) -and (Test-Path $usersCSVPath)) {
    $model    = Get-Content $modelPath    | ConvertFrom-Json
    $CSVNames = [System.Collections.ArrayList](Get-Content $usersCSVPath | ConvertFrom-Csv -Delimiter ";")
}
else {
    Write-Host "$modelPath or $usersCSVPath not present!" -ForegroundColor Red
    Exit
}

# --- [2] Check/Install ADDS role ---
$installing = $false
if ((Get-WindowsFeature AD-Domain-Services).Installed) {
    Write-Host "-------------------------"
    Write-Host '[i] ADDS already installed' -ForegroundColor Green
    try {
        $domain  = (Get-ADDomain).Forest
        $domainDN = (Get-ADRootDSE).rootDomainNamingContext
        Write-Host "    [i] $domain " -ForegroundColor Blue
        Write-Host "    [i] $domainDN" -ForegroundColor Blue
        Write-Host "-------------------------"
    }
    catch {
        Write-Host $_ -ForegroundColor Red
        Write-Host '[!] ADDS installed but no domain detected - is the server in a "WAITING TO PROMOTE" state ?' -ForegroundColor Red
        Write-Host '[!] Promote to DC and re-execute this script' -ForegroundColor Red
        Exit
    }
}
else {
    Write-Host "-------------------------"
    Write-Host '[!] ADDS not installed' -ForegroundColor Yellow
    $rep = Read-Host "    [?] Do you want to install Active Directory Domain Services ? (y/n)"
    if ($rep -like 'y*') {
        Write-Host "    [!] DSRM password will be: $($model.PSW)" -ForegroundColor Yellow
        $DSRMpsw = ConvertTo-SecureString $model.PSW -AsPlainText -Force
        $domain   = Read-Host "    [?] Please enter domain name (domain.tld)"
        try {
            Write-Host '[+] Installing ADDS role' -ForegroundColor Yellow
            Install-WindowsFeature AD-Domain-Services -IncludeAllSubFeature -IncludeManagementTools | Out-Null
            Write-Host '[+] Promoting server as Domain Controller' -ForegroundColor Yellow
            Write-Host '[i] EXPECT A REBOOT WARNING ONCE DONE' -ForegroundColor Yellow
            Install-ADDSForest -DomainName $domain -InstallDns -SafeModeAdministratorPassword $DSRMpsw -Force
            Write-Host '[!] You will be disconnected and must log in with the domain Administrator' -ForegroundColor Yellow
            Write-Host "-------------------------"
            $installing = $true
        }
        catch { Write-Host $_ -ForegroundColor Red }
    }
    else {
        Write-Host "[!] You chose not to install ADDS - Exiting" -ForegroundColor Red
        Exit
    }
}
if ($installing) { Exit }

# --- [3] Populate AD ---
Write-Host "[i] Base AD generation" -ForegroundColor Green

$protect = [bool]$model.PreventOUDeletion

# Root OU (idempotent)
$domainDN = (Get-ADRootDSE).defaultNamingContext
$RootOUdn = Ensure-OU -Name $model.RootOUName -Path $domainDN -Protect:$protect
Write-Host "    [+] Root OU: $RootOUdn" -ForegroundColor Yellow

# Standard top-level OUs under Root
$UsersTopOUdn     = Ensure-OU -Name $model.UsersBaseOU.OUName     -Path $RootOUdn -Protect:$protect
$ComputersTopOUdn = Ensure-OU -Name $model.ComputersOUs.OUName    -Path $RootOUdn -Protect:$protect
$GroupsTopOUdn    = Ensure-OU -Name $model.SecGroupsOUs.OUName    -Path $RootOUdn -Protect:$protect

# SubOUs for Computers
foreach ($c in $model.ComputersOUs.subOUs) {
    Ensure-OU -Name $c -Path $ComputersTopOUdn -Protect:$protect | Out-Null
}

# SubOUs for Groups (GGS, DLGS)
foreach ($g in $model.SecGroupsOUs.subOUs) {
    Ensure-OU -Name $g -Path $GroupsTopOUdn -Protect:$protect | Out-Null
}
$GGSOU  = (Get-ADOrganizationalUnit -Filter 'Name -eq "GGS"'  -SearchBase $GroupsTopOUdn).DistinguishedName
$DLGSOU = (Get-ADOrganizationalUnit -Filter 'Name -eq "DLGS"' -SearchBase $GroupsTopOUdn).DistinguishedName

# CustomOUs in your JSON are not an array; handle CustomNameN/subOUsN pairs
$model.CustomOUs.PSObject.Properties |
    Where-Object { $_.Name -like 'CustomName*' } |
    ForEach-Object {
        $idx = $_.Name.Substring('CustomName'.Length)
        $name = $_.Value
        $subKey = "subOUs$idx"
        $thisTop = Ensure-OU -Name $name -Path $RootOUdn -Protect:$protect
        $subs = $model.CustomOUs.$subKey
        if ($subs) {
            foreach ($s in $subs) { Ensure-OU -Name $s -Path $thisTop -Protect:$protect | Out-Null }
        }
    }

Write-Host "-------------------------"
# --- Shares root folder (fix path check) ---
if (!(Test-Path $model.RootSharePath)) {
    New-Item -Path $model.RootSharePath -ItemType Directory | Out-Null

    # Break inheritance and strip *Users
    icacls $model.RootSharePath /inheritance:d | Out-Null
    $fACLs = Get-Acl $model.RootSharePath
    $toRemove = @()
    foreach ($rule in $fACLs.Access) {
        if ($rule.IdentityReference -like "*Users") { $toRemove += $rule }
    }
    foreach ($r in $toRemove) { $null = $fACLs.RemoveAccessRule($r) }
    Set-Acl $model.RootSharePath $fACLs

    Write-Host "[+] $($model.RootSharePath) prepared (Admin-only initially)" -ForegroundColor Yellow
} else {
    Write-Host "[i] $($model.RootSharePath) already exists" -ForegroundColor DarkYellow
}
Write-Host "-------------------------"

# --- Departments / Groups / Shares / Users ---
Write-Host "[i] Departments generation" -ForegroundColor Green
$Depts = ($model.Depts).PSObject.Properties
$domain = (Get-ADDomain).DNSRoot

$psw = ConvertTo-SecureString $model.PSW -AsPlainText -Force

foreach ($dept in $Depts) {
    $deptFull  = $dept.Name
    $deptShort = $dept.Value

    Write-Host "    [i] $deptFull" -ForegroundColor Blue

    # Department OU under Users OU
    $deptDN = Ensure-OU -Name $deptFull -Path $UsersTopOUdn -Protect:$protect
    Write-Host "        [+] $deptFull OU" -ForegroundColor Yellow

    # Security Groups
    Ensure-Group -Name "GGS_${deptShort}_ALL"      -Path $GGSOU  -Category Security -Scope Global
    Ensure-Group -Name "GGS_${deptShort}_Managers" -Path $GGSOU  -Category Security -Scope Global
    Ensure-Group -Name "GGS_${deptShort}_Users"    -Path $GGSOU  -Category Security -Scope Global

    Ensure-Group -Name "DLGS_${deptShort}_Share_RO" -Path $DLGSOU -Category Security -Scope DomainLocal
    Ensure-Group -Name "DLGS_${deptShort}_Share_RW" -Path $DLGSOU -Category Security -Scope DomainLocal

    # Group nesting (idempotent)
    Ensure-GroupMember -Group "DLGS_${deptShort}_Share_RW" -Member "GGS_${deptShort}_Managers"
    Ensure-GroupMember -Group "DLGS_${deptShort}_Share_RO" -Member "GGS_${deptShort}_Users"

    # Department Share (SMB and NTFS)
    $DeptSharePath = Join-Path $model.RootSharePath $deptFull
    if (!(Test-Path $DeptSharePath)) {
        New-Item -Path $DeptSharePath -ItemType Directory | Out-Null
        # SMB share named with short name
        if (-not (Get-SmbShare -Name $deptShort -ErrorAction SilentlyContinue)) {
            New-SmbShare -Name $deptShort -Path $DeptSharePath | Out-Null
            Grant-SmbShareAccess -Name $deptShort -AccountName 'Everyone' -AccessRight Full -Force | Out-Null
        }
        # NTFS
        $dirACL = Get-Acl $DeptSharePath
        $acrw = New-Object System.Security.AccessControl.FileSystemAccessRule("DLGS_${deptShort}_Share_RW","Modify","ContainerInherit,ObjectInherit","None","Allow")
        $acro = New-Object System.Security.AccessControl.FileSystemAccessRule("DLGS_${deptShort}_Share_RO","ReadAndExecute","ContainerInherit,ObjectInherit","None","Allow")
        $dirACL.SetAccessRule($acrw)
        $dirACL.AddAccessRule($acro)
        Set-Acl -Path $DeptSharePath -AclObject $dirACL
        Start-Sleep -Milliseconds 100
        Write-Host "        [+] Share ready (SMB & NTFS): $DeptSharePath" -ForegroundColor Yellow
    } else {
        Write-Host "        [!] Share folder exists, skipping SMB/NTFS: $DeptSharePath" -ForegroundColor DarkYellow
    }

    # --- Users ---
    if ($CSVNames.Count -lt (1 + [int]$model.UsersPerDept)) {
        Write-Host "        [!] Not enough names left in CSV to generate $deptFull users. Skipping users for this dept." -ForegroundColor Red
        continue
    }

    # Manager
    $mNames = Get-Random -InputObject $CSVNames
    $null = $CSVNames.Remove($mNames)
    $mDisplayName = "$($mNames.firstName) $($mNames.lastName)"
    $baseSam = ("{0}.{1}" -f $mNames.firstName,$mNames.lastName).ToLower()
    $ids = Get-UniqueSamUpn -BaseSam $baseSam -Domain $domain
    $mSAM = $ids.Sam
    $mUPN = $ids.Upn
    $mDesc = "[mgr-$deptShort] " + (Get-Random -InputObject $model.AdditionalDesc)

    if (-not (Get-ADUser -Filter 'SamAccountName -eq $mSAM' -ErrorAction SilentlyContinue)) {
        New-ADUser -Path $deptDN -Name $mDisplayName -DisplayName $mDisplayName `
            -GivenName $mNames.firstName -Surname $mNames.lastName `
            -SamAccountName $mSAM -UserPrincipalName $mUPN -EmailAddress $mUPN `
            -AccountPassword $psw -ChangePasswordAtLogon $false -PasswordNeverExpires $true -Enabled $true `
            -Description $mDesc -Department $deptFull -ErrorAction Stop
    }
    Ensure-GroupMember -Group "GGS_${deptShort}_ALL"      -Member $mSAM
    Ensure-GroupMember -Group "GGS_${deptShort}_Managers" -Member $mSAM

    # Users
    for ($i=0; $i -lt [int]$model.UsersPerDept; $i++) {
        $uNames = Get-Random -InputObject $CSVNames
        $null = $CSVNames.Remove($uNames)

        $uDisplayName = "$($uNames.firstName) $($uNames.lastName)"
        $uBaseSam = ("{0}.{1}" -f $uNames.firstName,$uNames.lastName).ToLower()
        $uids = Get-UniqueSamUpn -BaseSam $uBaseSam -Domain $domain
        $uSAM = $uids.Sam
        $uUPN = $uids.Upn
        $uDesc = "[$deptShort] " + (Get-Random -InputObject $model.AdditionalDesc)

        if (-not (Get-ADUser -Filter 'SamAccountName -eq $uSAM' -ErrorAction SilentlyContinue)) {
            New-ADUser -Path $deptDN -Name $uDisplayName -DisplayName $uDisplayName `
                -GivenName $uNames.firstName -Surname $uNames.lastName `
                -SamAccountName $uSAM -UserPrincipalName $uUPN -EmailAddress $uUPN `
                -AccountPassword $psw -ChangePasswordAtLogon $false -PasswordNeverExpires $true -Enabled $true `
                -Description $uDesc -Department $deptFull -Manager $mSAM -ErrorAction Stop
        }
        Ensure-GroupMember -Group "GGS_${deptShort}_ALL"   -Member $uSAM
        Ensure-GroupMember -Group "GGS_${deptShort}_Users" -Member $uSAM
    }

    Write-Host "        [+] $deptFull Manager & Users done" -ForegroundColor Yellow
    Write-Host "    ---------------------"
}

Write-Host "-------------------------"
Write-Host "[✓] Completed without duplicate-object errors." -ForegroundColor Green
