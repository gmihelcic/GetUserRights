# GetUserRights
Checking all user Rights on the target computer

The purpose of this utility is to check resultant user rights on the computer where utility is ran both comming from GPO or Local Security Policy.

Usage:

GetUserRights [[domain\]username]

In case you don't provide user rights are checked for logged on user.

Examples:

1. Checking rights for logged on user:

GetUserRights

2. Checking rights for local computer user:

GetUserRights .\UserName

3. Checking rights for domain user:

GetUserRights Domain\UserName


