# Get unconstrained delegation hosts EXCLUDING DCs
Get-DomainComputer -Unconstrained | Where-Object {
    $_.useraccountcontrol -notmatch "SERVER_TRUST_ACCOUNT"
} | Select-Object dnshostname, operatingsystem, useraccountcontrol


# Unconstrained delegation — can capture any TGT that authenticates to it
Get-DomainComputer -Unconstrained
Get-DomainUser -Unconstrained  # <-- check if your svc acct is here

# Constrained delegation — can impersonate any user to specific services
Get-DomainUser -TrustedToAuth | Select-Object samaccountname, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth



# What can this service account do to other objects?
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {
    $_.IdentityReferenceName -match "<svcaccount>"
}

# Common jackpots:
# GenericAll on a user → reset their password
# WriteDACL on domain → give yourself DCSync rights
# GenericAll on a group → add yourself
