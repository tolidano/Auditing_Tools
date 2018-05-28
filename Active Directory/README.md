Most of the scripts here are not written by me and has been collated and uploaded here from various online sources for easy reference and use.
Original source links has been given wherever applicable.

Get-GPOInfo 
-----------
Source : https://gallery.technet.microsoft.com/scriptcenter/Get-GPO-informations-b02e0fdf

This powershell script helps extracting all the information relating to a GPO such as created date, modified date etc. from the Active Directory Server.

Get-GPOPermissions 
------------------

Custom written powershell script with help of various online sources.
This powershell script extracts all permissions of Group Policy. These permissions are given out in GUID format. Majorly helps in identifying in case any specific object has been exempted from following a policy. 

Note: 
GUID for "Apply Group Policy" permission is "edacfd8f-ffb3-11d1-b41d-00a0c968f939". Check for "Deny" Value  for the GUID to confirm if a specific AD Object has been exempted from following the GPO.

Get-GPOStatus 
-------------
Source: https://gallery.technet.microsoft.com/PowerShell-Script-to-eed7188a

This script gives out informations on where the GPO resides, it's status etc into a csv file in the same directory from where the script is run. The hardcoded name of the output csv file is "GPO_Status_Report.csv".

Other One Liner commands
------------------------

1. Extract all GPO Reports to one html file

   Get-GPOReport -All -Reporttype html | Out-File <Path_of_the_Output_File>

2. Extract all AD Objects from the domain  with attributes

   i. csvde -f output.csv (Outputs the entire AD Objects with all the properties/ attributes to a csv file, heavy on AD Server)

   ii. dsquery * domainroot -attr samaccountname samaccounttype description useraccountcontrol whenCreated whenchanged accountexpires lastlogon lastlogontimestamp lastlogoff memberof –limit 0 > Userlist.txt (Outputs the entire AD Objects to a csv file, heavy on AD Server)

   Note:- 
        There are many attributes that can be used with the above command. Find the list of supported attributes in the below link :-
        https://pastebin.com/mYD1Qk0L




