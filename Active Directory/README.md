This folder consists of scripts that are used by me to audit Active Directory related controls.


Disclaimer : 
------------

Most of the scripts here are not written by me and has been collated and uploaded here from various online sources for easy reference and use. Original source links has been given wherever applicable.

Get-FullGPOInfo 
---------------
This script extracts all the Metadata of all existing GPOs in a domain controller.

This script consists of codes from various online sources with little bit of customisations from my side for personal use. The original source of the scripts utilised in this , has been given below.

Source : 
1. https://gallery.technet.microsoft.com/scriptcenter/Get-GPO-informations-b02e0fdf
2. https://gallery.technet.microsoft.com/PowerShell-Script-to-eed7188a


Quick Reference One-Liner Commands
----------------------------------
Note: This section will be updated as and when I find any one liner commands being useful in my audit journey.

1. Extract all GPO Reports to one html/xml file

   Get-GPOReport -All -Reporttype < html / XML> | Out-File <Path_of_the_Output_File>

2. Extract all AD Objects from the root domain with attributes

   i. csvde -f output.csv (Outputs the entire AD Objects with all the properties/ attributes to a csv file, heavy on AD Server)

   ii. dsquery * domainroot -attr samaccountname samaccounttype description useraccountcontrol whenCreated whenchanged accountexpires lastlogon lastlogontimestamp lastlogoff memberof –limit 0 > Userlist.txt (Outputs the entire AD Objects to a csv file, heavy on AD Server)

   Note:- 
        There are many attributes that can be used with the above dsquery command. Find the list of supported attributes in the below link :-
        https://pastebin.com/mYD1Qk0L




