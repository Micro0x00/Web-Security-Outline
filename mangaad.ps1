Param(
        [string]$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.name ,
        [string]$ObjType = '' ,
        [string]$Propertie = '',
        [string]$DN = ([ADSI]'').distinguishedName,
        [string]$Name = ''
)
Set-Variable -Name LDAPpath -Value ("LDAP://$pdc/$dn")
Set-Variable -Name Entry -Value (New-Object System.DirectoryServices.DirectoryEntry("$LDAPpath"))



function Users-S {
        Set-Variable -Name DirSerUsers -Value (New-Object System.DirectoryServices.DirectorySearcher($Entry,"(&(objectCategory=User)(objectClass=User)(samAccountType=805306368))"))
        Set-Variable -Name Users -Value ($DirSerUsers.FindALL())
        if($Propertie -ne '' -and $Propertie -ne "*" -and $Name -ne ''){
                $Obj = $Users | Where-Object { $_.Properties["sAMAccountName"] -eq "$Name" -or $_.Properties["cn"] -eq "$Name"}
                $Obj.Properties["$Propertie"]
                break
        }
        if($Propertie -eq "*" -and $Name -ne ''){
                $Obj = $Users | Where-Object { $_.Properties["sAMAccountName"] -eq "$Name" -or $_.Properties["cn"] -eq "$Name"}
                $Obj.Properties
                break
        }
        else{

        Set-Variable -Name SPNList -Value (@())
        Write-Host -BackgroundColor Yellow  -ForegroundColor Red "-------------- Users -----------------"
        foreach( $User in $Users ){
                Set-Variable -Name userAccountControl -Value ([System.Int32]$User.Properties["userAccountControl"][0])
                if($User.Properties["serviceprincipalname"] -ne $null){
                $SPNList += $User
                }else {


                        if($User.Properties["description"] -ne $null ){
                                write-host "=> "$User.Properties["sAMAccountName"]
                                write-host  -ForegroundColor Yellow "Comment : "$User.Properties.description

                                }
                        if(($userAccountControl -band 0x400000) -eq 0x400000){
                                write-host "=> "$User.Properties["sAMAccountName"] -ForegroundColor Red " <= AS-REP Roasting"


                                }

                        else{
                        write-host "=> "$User.Properties["sAMAccountName"]
                                }
                        }

        }

        write-host "----------------ServicePrincipalName-------------------"
        foreach ($SPN in $SPNList){
                write-host  -ForegroundColor Green "SPN : "$SPN.Properties["serviceprincipalname"]
                write-host  -ForegroundColor Green "SPN-Name : "$SPN.Properties["sAMAccountName"]
                if($SPN.Properties.description -ne $null ){
                        write-host  -ForegroundColor Yellow "Comment : "$SPN.Properties["description"]
                }
                write-host "MemberOF : "
                $SPN.Properties["memberof"]
                write-host "-----------------------------------"
        }}

}
function Machines-S {
        Set-Variable -Name DirSerMachines -Value (New-Object System.DirectoryServices.DirectorySearcher($Entry,"(&(objectCategory=computer)(objectClass=computer)(samAccountType=805306369))"))
        Set-Variable -Name Machines -Value ($DirSerMachines.FindALL())
        if($Propertie -ne '' -and $Propertie -ne "*" -and $Name -ne ''){
                $Obj = $Machines | Where-Object { $_.Properties["sAMAccountName"] -eq "$Name" -or $_.Properties["cn"] -eq "$Name"}
                $Obj.Properties["$Propertie"]
                break
        }
        if($Propertie -eq "*" -and $Name -ne ''){
                $Obj = $Machines | Where-Object { $_.Properties["sAMAccountName"] -eq "$Name" -or $_.Properties["cn"] -eq "$Name"}
                $Obj.Properties
                break
        }
        else{
        Write-Host -ForegroundColor Red  -BackgroundColor Yellow "-------------  Machine ------------------"
        foreach( $Machine in $Machines ){
                write-host " sAMAccountName : " $Machine.Properties["sAMAccountName"]
                write-host " DNShostName : " $Machine.Properties["dnshostname"]
                write-host " OperatingSystem : " $Machine.Properties["operatingsystem"]
                write-host " OS-Version : " $Machine.Properties["operatingsystemversion"]
                Write-Host "--------------------"
}

}}
function Groups-S {
        Set-Variable -Name DirSerGroups -Value (New-Object System.DirectoryServices.DirectorySearcher($Entry,"(&(objectCategory=group)(objectClass=group))"))
        Set-Variable -Name Groups -Value ($DirSerGroups.FindALL())
        if($Propertie -ne '' -and $Propertie -ne "*" -and $Name -ne ''){
                $Obj = $Groups | Where-Object { $_.Properties["sAMAccountName"] -eq "$Name" -or $_.Properties["cn"] -eq "$Name"}
                $Obj.Properties["$Propertie"]
                break
        }
        if($Propertie -eq "*" -and $Name -ne ''){
                $Obj = $Groups | Where-Object { $_.Properties["sAMAccountName"] -eq "$Name" -or $_.Properties["cn"] -eq "$Name"}
                $Obj.Properties
                break
        }else{
        Write-Host  -ForegroundColor Red  -BackgroundColor Yellow "-------------- Groups -----------------"
        foreach( $Group in $Groups ){


                Set-Variable -Name S -Value ($false)
                Set-Variable -Name GroupName -Value ("")
                Foreach ($DefaultGroup in $GroupList){

                        if( $Group.Properties["sAMAccountName"] -eq $DefaultGroup ){
                        $S  = $true

                        break
                        }

                }
                if ($S){


                Write-Host -ForegroundColor Red  $Group.Properties.cn
                }else{
                Write-Host -ForegroundColor Green  $Group.Properties["sAMAccountName"]  "<=Custom Group"
                Write-Host -ForegroundColor yellow "Member : "
                 $Group.Properties["member"]
                Write-Host  -ForegroundColor yellow "MemberOF : "
                 $Group.Properties["memberof"]


                }

        }


}}

Set-Variable -Name GroupList -Value (@(
"Access Control Assistance Operators",
"Account Operators",
"Administrators",
"Allowed RODC Password Replication",
"Backup Operators",
"Certificate Service DCOM Access",
"Cert Publishers",
"Cloneable Domain Controllers",
"Cryptographic Operators",
"Denied RODC Password Replication",
"Device Owners",
"DHCP Administrators",
"DHCP Users",
"Distributed COM Users",
"DnsUpdateProxy",
"DnsAdmins",
"Domain Admins",
"Domain Computers",
"Domain Controllers",
"Domain Guests",
"Domain Users",
"Enterprise Admins",
"Enterprise Key Admins",
"Enterprise Read-only Domain Controllers",
"Event Log Readers",
"Group Policy Creator Owners",
"Guests",
"Hyper-V Administrators",
"IIS_IUSRS",
"Incoming Forest Trust Builders",
"Key Admins",
"Network Configuration Operators",
"Performance Log Users",
"Performance Monitor Users",
"Print Operators",
"Protected Users",
"RAS and IAS Servers",
"RDS Endpoint Servers",
"RDS Management Servers",
"RDS Remote Access Servers",
"Read-only Domain Controllers",
"Remote Desktop Users",
"Remote Management Users",
"Replicator",
"Schema Admins",
"Server Operators",
"Storage Replica Administrators",
"System Managed Accounts",
"System Managed Accounts Group",
"Terminal Server License Servers",
"Users",
"Windows Authorization Access",
"WinRMRemoteWMIUsers_",
"Allowed RODC Password Replication Group",
"Denied RODC Password Replication Group",
"Windows Authorization Access Group",
"Pre-Windows 2000 Compatible Access"

#security groups
))
switch ($ObjType) {
    "G" {
        Groups-S
    }
    "M" {
        Machines-S
    }
    "U" {
        Users-S
    }
    Default {
                Users-S
                Machines-S
                Groups-S
    }
}



