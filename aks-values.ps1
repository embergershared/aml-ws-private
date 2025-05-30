Function AddLog ($message) {
  #Add-Content -Path $filePath -Value "$(Get-Date): $message"
  Write-Host "$(Get-Date): $message"
}

$SUFFIX = "use2-391575-s4-aml-ws-private"
$LOC = "eastus2"



# $VM_USER_NAME = "winboxadm5"

# $VM_PUBLIC_PORT = "58995"

# $SUBSC_ID = "4c88693f-5cc9-4f30-9d1e-d58d4221cf25"
# $ACR_NAME = "acrakslzaccel234"

# $AKS_STORE_PUBLIC_PORT = "58374"
# $AKS_ING_PUBLIC_PORT = "80"

AddLog "Sourced Variables initialized"

