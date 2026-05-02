# Get unconstrained delegation hosts EXCLUDING DCs
Get-DomainComputer -Unconstrained | Where-Object {
    $_.useraccountcontrol -notmatch "SERVER_TRUST_ACCOUNT"
} | Select-Object dnshostname, operatingsystem, useraccountcontrol


