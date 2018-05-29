Function Get-GPOInfo { 
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
					If ($SOM.gPLink.length -gt 1) {
						$links = @($SOM.gPLink -split {$_ -eq '[' -or $_ -eq ']'} | Where-Object {$_}) 
						For ( $i = $links.count - 1 ; $i -ge 0 ; $i-- ) {
							$GPOData = $links[$i] -split {$_ -eq '/' -or $_ -eq ';'}
							$report += New-Object -TypeName PSCustomObject -Property @{
							Name              = $SOM.Name;
                            GUID              = "{$($GPOsHash[$($GPOData[2])].ID)}";
							Depth             = $SOM.Depth;
							Precedence        = $links.count - $i
							Config            = $GPOData[3];
							LinkEnabled       = [bool](!([int]$GPOData[3] -band 1));
							Enforced          = [bool]([int]$GPOData[3] -band 2);
							BlockInheritance  = [bool]($SOM.gPOptions -band 1)
							} 
						}
					} 
					Else {
						$report += New-Object -TypeName PSCustomObject -Property @{
						Depth             = $SOM.Depth;
						BlockInheritance  = [bool]($SOM.gPOptions -band 1)
						}
					}
           } 
		   Else {
            $report += New-Object -TypeName PSCustomObject -Property @{
            Depth             = $SOM.Depth;
            BlockInheritance  = [bool]($SOM.gPOptions -band 1)
				}
			} 
		}
        
        
        
        $domain= Get-ADDomain
        ForEach($GPO in (Get-GPO -All -Domain $DomainName )){ 
            Write-Verbose -Message "Processing $($GPO.DisplayName)..." 
            [xml]$XmlGPReport = $GPO.generatereport('xml') 
            #GPO version 
            if($XmlGPReport.GPO.Computer.VersionDirectory -eq 0 -and $XmlGPReport.GPO.Computer.VersionSysvol -eq 0){$ComputerSettings="NeverModified"}else{$ComputerSettings="Modified"} 
            if($XmlGPReport.GPO.User.VersionDirectory -eq 0 -and $XmlGPReport.GPO.User.VersionSysvol -eq 0){$UserSettings="NeverModified"}else{$UserSettings="Modified"} 
            #GPO content 
            if($XmlGPReport.GPO.User.ExtensionData -eq $null){$UserSettingsConfigured=$false}else{$UserSettingsConfigured=$true} 
            if($XmlGPReport.GPO.Computer.ExtensionData -eq $null){$ComputerSettingsConfigured=$false}else{$ComputerSettingsConfigured=$true} 
            #Output 
            $adgpo = [ADSI]"LDAP://CN=`{$($GPO.id)`},CN=Policies,CN=System,$domain"
            $acl = $adgpo.ObjectSecurity
            $index=-1
            
            For ( $i = 0;$i -le $report.count;$i++ ) 
            {
                     
               if((($report[$i].Guid.tostring() -replace "{","") -replace "}","") -eq $GPO.ID)
               {
                  $index=$i
                  break
               }
             }
            $sm=  $report[$index].Name.PadLeft($report[$index].name.length + ($report[$index].depth * 5),'_')             
            
            New-Object -TypeName PSObject -Property @{ 
                
                'Depth'              = $report[$index].Depth
                'Precedence'         = $report[$index].Precedence
                'Config'             = $report[$index].Config
                'LinkEnabled'        = $report[$index].LinkEnabled
                'Enforced'           = $report[$index].Enforced
                'BlockInheritance'   = $report[$index].BlockInheritance
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
                'Path'               = $GPO.Path 
                'Permissions'        = $acl.Access | ForEach-Object -Process { 
                    New-Object -TypeName PSObject -Property @{ 
                        'ActiveDirectory Rights'  = $_.ActiveDirectoryRights
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
        } 
    } 
 
}
Get-GPOInfo
