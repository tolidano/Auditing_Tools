<####################################################################################################################################################################################################################################################


Requires:
-PowerShell v3 or above
-RSAT 2012 or above for GPLinkMetadata (If not , it will throw a couple of errors when processing 
-AD PowerShell module
-Group Policy module
-Appropriate permissions

#####################################################################################################################################################################################################################################################>

Function Get-FullGPOInfo { 
    [cmdletbinding()] 
    Param( 
        [Parameter(Mandatory=$false)] 
        [ValidateScript({Test-Connection $_ -Count 1 -Quiet})] 
        [String]$DomainName=$env:USERDNSDOMAIN 
        
        ) 
 
    Begin{ 
        Write-Verbose -Message "Importing Group Policy module..." 
        try {
        Import-Module -Name GroupPolicy -Verbose:$false -ErrorAction stop
        Import-Module -Name ActiveDirectory -Verbose:$false -ErrorAction stop
        } 
        catch{Write-Warning -Message "Failed to import GroupPolicy / Active Directory module";continue} 
    } 
 
    Process{ 

########################################################################################################################################################################################################################################################

		Function Get-ADOrganizationalUnitOneLevel {
		param($Path)
			Get-ADOrganizationalUnit -Filter * -SearchBase $Path `
				-SearchScope OneLevel -Server $Server |
				Sort-Object Name |
				ForEach-Object {
					$script:OUHash.Add($_.DistinguishedName,$script:Counter++)
					Get-ADOrganizationalUnitOneLevel -Path $_.DistinguishedName}
		}

		Function Get-ADOrganizationalUnitSorted {
			$DomainRoot = (Get-ADDomain -Server $Server).DistinguishedName
			$script:Counter = 1
			$script:OUHash = @{$DomainRoot=0}
			Get-ADOrganizationalUnitOneLevel -Path $DomainRoot
			$OUHash
		}

		$SortedOUs = Get-ADOrganizationalUnitSorted
        

##########################################################################################################################################################################################################################################################



        $GPOs = Get-GPO -All | Select-Object ID, Path, DisplayName, GPOStatus, WMIFilter
        $GPOsHash = @{}
        ForEach ($GPO in $GPOs) 
        {$GPOsHash.Add($GPO.Path,$GPO)}
        $gPLinks = @()
        $gPLinks += `
		Get-ADObject -Identity (Get-ADDomain).distinguishedName -Properties name, distinguishedName, gPLink, gPOptions |Select-Object name, distinguishedName, gPLink, gPOptions, @{name='Depth';expression={0}}
		
        $gPLinks += `
        Get-ADOrganizationalUnit -Filter * -Properties name, distinguishedName, gPLink, gPOptions | Select-Object name, distinguishedName, gPLink, gPOptions, @{name='Depth';expression={($_.distinguishedName -split 'OU=').count - 1}}
		
        $gPLinks += `
        Get-ADObject -LDAPFilter '(objectClass=site)' -SearchBase "CN=Sites,$((Get-ADRootDSE).configurationNamingContext)" -SearchScope OneLevel -Properties name, distinguishedName, gPLink, gPOptions |
        Select-Object name, distinguishedName, gPLink, gPOptions, @{name='Depth';expression={0}}
        
		$report = @()
        
		ForEach ($SOM in $gPLinks) {
			If ($SOM.gPLink) {

            #The below command Get-ADReplicationAttributeMetadata would work only in AD Server 2012 and above.Ignore the errors in other OS.            
            $gPLinkMetadata = Get-ADReplicationAttributeMetadata -Server $Server -Object $SOM.distinguishedName -Properties gPLink

                    $order+=1
					If ($SOM.gPLink.length -gt 1) {
						$links = @($SOM.gPLink -split {$_ -eq '[' -or $_ -eq ']'} | Where-Object {$_}) 
						For ( $i = $links.count - 1 ; $i -ge 0 ; $i-- ) {
							$GPOData = $links[$i] -split {$_ -eq '/' -or $_ -eq ';'}
							$report += New-Object -TypeName PSCustomObject -Property @{
							Name              = $SOM.Name;
                            DistinguishedName = $SOM.distinguishedName
                            GUID              = $($GPOsHash[$($GPOData[2])].ID);
							Depth             = $SOM.Depth;
                            BlockInheritance  = [bool]($SOM.gPOptions -band 1)
                            gPLinkVersion     = $gPLinkMetadata.Version
                            gPLinkLastOrigChgTime = $gPLinkMetadata.LastOriginatingChangeTime
                            gPLinkLastOrigChgDirServerId = $gPLinkMetadata.LastOriginatingChangeDirectoryServerIdentity
                            gPLinkLastOrigChgDirServerInvocId = $gPLinkMetadata.LastOriginatingChangeDirectoryServerInvocationId
							} 
						}
					} 
					Else {
						$report += New-Object -TypeName PSCustomObject -Property @{
                        Depth             = $SOM.Depth;
                        Name              = $SOM.Name;
                        DistinguishedName = $SOM.distinguishedName;
						BlockInheritance  = [bool]($SOM.gPOptions -band 1)
                        gPLinkVersion     = $gPLinkMetadata.Version
                        gPLinkLastOrigChgTime = $gPLinkMetadata.LastOriginatingChangeTime
                        gPLinkLastOrigChgDirServerId = $gPLinkMetadata.LastOriginatingChangeDirectoryServerIdentity
                        gPLinkLastOrigChgDirServerInvocId = $gPLinkMetadata.LastOriginatingChangeDirectoryServerInvocationId
						}
					}
           } 
		   Else {
            $report += New-Object -TypeName PSCustomObject -Property @{
            Depth             = $SOM.Depth;
            Name              = $SOM.Name;
            DistinguishedName = $SOM.distinguishedName;
            BlockInheritance  = [bool]($SOM.gPOptions -band 1)
				}
			} 
		}
        
##########################################################################################################################################################################################################################################################        
       
        $domain= Get-ADDomain
        ForEach ($path in $gpLinks)
		{
            $guidindex=-1
            $ouindex=-1
            
            For ( $i = 0;$i -le $report.count;$i++ ) 
            {
                     
               if(($report[$i].Guid -eq $Guid.gpoid ) -and ($guidindex -eq -1))
               {
                  $guidindex=$i
                                 
               }

               if (($report[$i].distinguishedname  -eq $path.distinguishedname ) -and ($ouindex -eq -1))
               {
                  $ouindex=$i
                  
               }

               if ($guidindex -ne -1 -and $ouindex -ne -1){
               break}

             }
            $sm=  $report[$ouindex].Name.PadLeft($report[$ouindex].name.length + ($report[$ouindex].depth * 5),'_')             
            

            $gpinheritance=(Get-GPInheritance -path $path.distinguishedname).gpolinks
			if ($gpinheritance -ne {}){
        ForEach($GP in $gpinheritance){ 
			
            Write-Verbose -Message "Processing $($GPO.DisplayName)..." 
            
            ForEach ($guid in $GP){
			
            [xml]$XmlGPReport = Get-GPOReport -Guid $Guid.gpoid -ReportType xml
			$GPO = Get-GPO -guid $Guid.gpoid
            #GPO version 
            if($XmlGPReport.GPO.Computer.VersionDirectory -eq 0 -and $XmlGPReport.GPO.Computer.VersionSysvol -eq 0){$ComputerSettings="NeverModified"}else{$ComputerSettings="Modified"} 
            if($XmlGPReport.GPO.User.VersionDirectory -eq 0 -and $XmlGPReportG.GPO.User.VersionSysvol -eq 0){$UserSettings="NeverModified"}else{$UserSettings="Modified"} 
            #GPO content 
            if($XmlGPReport.GPO.User.ExtensionData -eq $null){$UserSettingsConfigured=$false}else{$UserSettingsConfigured=$true} 
            if($XmlGPReport.GPO.Computer.ExtensionData -eq $null){$ComputerSettingsConfigured=$false}else{$ComputerSettingsConfigured=$true} 
            #Output 
            $adgpo = [ADSI]"LDAP://CN=`{$($GPO.id)`},CN=Policies,CN=System,$domain"
            $acl = $adgpo.ObjectSecurity
            $sacl = (Get-ACL -Audit -Path "AD:\$($GPO.path)").Audit
            
			New-Object -TypeName PSObject -Property @{ 
                
                'Depth'              = $report[$ouindex].Depth
                'Description'        = $GPO.Description
                'Precedence'         = $guid.order
                'SACL'               = $sacl | ForEach-Object -Process { 
                    New-Object -TypeName PSObject -Property @{ 
                        'ActiveDirectory Rights'  = $_.ActiveDirectoryRights
                        'Inheritance Type'        = $_.InheritanceType
                        'Object Type'             = $_.ObjectType
                        'Inherited ObjectType'    = $_.InheritedObjectType
                        'Object Flags'            = $_.ObjectFlags
                        'Audit Flags'             = $_.AuditFlag
                        'Access Control Type'     = $_.AccessControlType
                        'Identity Reference'      = $_.Identityreference
                        'Is Inherited'            = $_.Isinherited
                        'Inheritance Flags'       = $_.InheritanceFlags
                        'Propogation Flags'       = $_.Propogationflags

                    } 
                    }
                'SortOrder'          = $sortedous[$path.distinguishedname]               
                'LinkEnabled'        = $guid.Enabled
                'Enforced'           = $guid.Enforced
                'BlockInheritance'   = $report[$ouindex].BlockInheritance
                'SOM'                = $sm
                'LinksTO'            = $XmlGPReport.GPO.LinksTo | Select-Object -ExpandProperty SOMPath 
                'Name'               = $XmlGPReport.GPO.Name 
                'ComputerSettings'   = $ComputerSettings 
                'UserSettings'       = $UserSettings 
                'SDDL'               = $XmlGPReport.GPO.SecurityDescriptor.SDDL.'#text'
                'UserEnabled'        = $XmlGPReport.GPO.User.Enabled 
                'ComputerEnabled'    = $XmlGPReport.GPO.Computer.Enabled 
                'HasComputerSettings'= $ComputerSettingsConfigured 
                'HasUserSettings'    = $UserSettingsConfigured 
                'CreationTime'       = $GPO.CreationTime 
                'ModificationTime'   = $GPO.ModificationTime 
                'GpoStatus'          = $GPO.GpoStatus 
                'GUID'               = $GPO.Id 
                'WMIFilter'          = $GPO.WmiFilter.name,$GPO.WmiFilter.Description 
                'GPOPath'            = $GPO.Path 
                'SOMPath'            = $path.distinguishedname
                'gPLinkVersion'     = $report[$guidindex].gPLinkVersion
                'gPLinkLastOrigChgTime' = $report[$guidindex].gPLinkLastOrigChgTime
                'gPLinkLastOrigChgDirServerId' = $report[$guidindex].gPLinkLastOrigChgDirServerId
                'gPLinkLastOrigChgDirServerInvocId' = $report[$guidindex].gPLinkLastOrigChgDirServerInvocId
                'Permissions'        = $acl.Access | ForEach-Object -Process { 
                    New-Object -TypeName PSObject -Property @{ 
                        'ActiveDirectorRights'  = $_.ActiveDirectoryRights
                        'Inheritance Type'        = $_.InheritanceType
                        'Object Type'             = $_.ObjectType
                        'Inherited ObjectType'    = $_.InheritedObjectType
                        'Object Flags'            = $_.ObjectFlags
                        'Access Control Type'     = $_.AccessControlType
                        'Identity Reference'      = $_.Identityreference
                        'Is Inherited'            = $_.Isinherited
                        'Inheritance Flags'       = $_.InheritanceFlags
                        'Propogation Flags'       = $_.Propogationflags

                    }
                }
            }
             
        } }
		}#
		
		else 
		
		{
		
			New-Object -TypeName PSObject -Property @{ 
                
                'Depth'              = $report[$ouindex].Depth
                'Precedence'         = ""
                'SortOrder'           =$sortedous[$path.distinguishedname]               
                'LinkEnabled'        = ""
                'SACL'               = ""
                'Enforced'           = ""
                'BlockInheritance'   = $report[$ouindex].BlockInheritance
                'SOM'                = $sm
                'LinksTO'            = "" 
                'Name'               = "" 
                'ComputerSettings'   = "" 
                'UserSettings'       = "" 
                'SDDL'               = ""
                'UserEnabled'        = "" 
                'ComputerEnabled'    = "" 
                'HasComputerSettings'= "" 
                'HasUserSettings'    = "" 
                'CreationTime'       = "" 
                'ModificationTime'   = "" 
                'GpoStatus'          = "" 
                'GUID'               = "" 
                'WMIFilter'          = "" 
                'GPOPath'            = "" 
                'SOMPath'            = $path.distinguishedname
                'gPLinkVersion'     = ""
                'gPLinkLastOrigChgTime' = ""
                'gPLinkLastOrigChgDirServerId' = ""
                'gPLinkLastOrigChgDirServerInvocId' = ""
                'Permissions'        = "" 
            }
			
						
		}#
    } 
 
}}
Get-FullGpoinfo | Select-Object SOM,SOMpath,SortOrder,Depth,Name,GUID,GPOpath,LinkEnabled,Enforced,Precedence,BlockInheritance,Linksto,CreationTime,ModificationTime,GPOStatus,HasComputerSettings,ComputerSettings,ComputerEnabled,HasUserSettings,UserSettings,UserEnabled,Wmifilter,gPLinkVersion,gPLinkLastOrigChgTime,gPLinkLastOrigChgDirServerId,gPLinkLastOrigChgDirServerInvocId,Permissions,SDDL,SACL| Sort-Object SortOrder,Precedence | Out-GridView

