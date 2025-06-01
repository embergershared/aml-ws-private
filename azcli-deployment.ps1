# Functions
function AddLog ($message) {
  #Add-Content -Path $filePath -Value "$(Get-Date): $message"
  Write-Host "$(Get-Date): $message"
}
function TrimAndRemoveTrailingHyphens {
  param(
    [Parameter(Mandatory = $true)]
    [string]$inputString,
        
    [Parameter(Mandatory = $true)]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$maxLength
  )

  # First trim the string to the maximum length
  $trimmedString = $inputString.Substring(0, [System.Math]::Min($maxLength, $inputString.Length))
    
  # Remove any trailing hyphens
  $trimmedString = $trimmedString.TrimEnd('-')
    
  # Remove any leading hyphens
  $trimmedString = $trimmedString.TrimStart('-')
    
  return $trimmedString
}
function GeneratePassword {
  param(
    [ValidateRange(12, 256)]
    [int] 
    $length = 14
  )

  $symbols = '!@#$%^&*'.ToCharArray()
  $characterList = 'a'..'z' + 'A'..'Z' + '0'..'9' + $symbols
  do {
    $password = -join (0..$length | ForEach-Object { $characterList | Get-Random })
    [int]$hasLowerChar = $password -cmatch '[a-z]'
    [int]$hasUpperChar = $password -cmatch '[A-Z]'
    [int]$hasDigit = $password -match '[0-9]'
    [int]$hasSymbol = $password.IndexOfAny($symbols) -ne -1
  }
  until (($hasLowerChar + $hasUpperChar + $hasDigit + $hasSymbol) -ge 3)

  return $password #| ConvertTo-SecureString -AsPlainText
}
function CreatePrivateEndpoint {
  param(
    [string]$name,
    [string]$resourceId,
    [string]$groupId,
    [string]$dnsZoneName,
    [string]$rgName,
    [string]$vnetName,
    [string]$subnetName
  )

  # Create private endpoint
  az network private-endpoint create `
    --name "$name-pe" `
    --resource-group $rgName `
    --vnet-name $vnetName `
    --subnet $subnetName `
    --private-connection-resource-id $resourceId `
    --group-id $groupId `
    --connection-name "$name-pe-conn" `
    --nic-name "$name-pe-nic"

  # Create DNS zone group for automatic DNS registration
  az network private-endpoint dns-zone-group create `
    --name "pe-dns-zone-group" `
    --resource-group $rgName `
    --endpoint-name "$name-pe" `
    --private-dns-zone $dnsZoneName `
    --zone-name default
    
  AddLog "Private endpoint created: $name"
}
AddLog "Functions loaded"

# Sourced variables
$valuesPath = Join-Path $PSScriptRoot "azcli-values.ps1"
if (-not (Test-Path $valuesPath)) {
  Write-Error "Values file not found at: $valuesPath"
  exit 1
}
. $valuesPath
AddLog "Values from azcli-values.ps1 sourced"

# Generated variables
$RG_NAME = "rg-${SUFFIX}"
$VNET_NAME = "vnet-${SUFFIX}"
$VNET_ADDRESS_PREFIX = "192.168.42.0/23"
$WKLD_SUBNET_NAME = "wkld-snet"
$WKLD_SUBNET_ADDRESS_PREFIX = "192.168.43.0/24"

$AZFW_NAME = "azfw-${SUFFIX}"
$AZFW_SUBNET_PREFIX = "192.168.42.0/26"
$AZFW_MGMT_SUBNET_PREFIX = "192.168.42.64/26"
$AZFW_PUBLICIP_NAME = "pip-for-azfw-${SUFFIX}"
$AZFW_IPCONFIG_NAME = "azfw-ipconfig-${SUFFIX}"
$AZFW_ROUTE_TABLE_NAME = "udr-${SUFFIX}"
$AZFW_ROUTE_NAME = "next-hop-v-appliance-to-azfw-private-ip"
$AZFW_ROUTE_NAME_INTERNET = "next-hop-internet-to-azfw-public-ip"

$BASTION_NAME = "bastion-${SUFFIX}"
$BASTION_PIP_NAME = "pip-for-bastion-${SUFFIX}"
$BASTION_SUBNET_ADDRESS_PREFIX = "192.168.42.128/26"

$KV_NAME = TrimAndRemoveTrailingHyphens -inputString "kv-${SUFFIX}" -maxLength 24
$LAW_NAME = TrimAndRemoveTrailingHyphens -inputString "law-${SUFFIX}" -maxLength 15
$ST_NAME = (TrimAndRemoveTrailingHyphens -inputString "st-${SUFFIX}" -maxLength 24).Replace("-", "").ToLower()
$APP_INS_NAME = TrimAndRemoveTrailingHyphens -inputString "appi-${SUFFIX}" -maxLength 260
$ACR_NAME = (TrimAndRemoveTrailingHyphens -inputString "acr-${SUFFIX}" -maxLength 24).Replace("-", "").ToLower()
$APP_INS_NAME = TrimAndRemoveTrailingHyphens -inputString "appi-${SUFFIX}" -maxLength 260
$AML_WS_NAME = TrimAndRemoveTrailingHyphens -inputString "amlws-${SUFFIX}" -maxLength 24

$VM_NAME = TrimAndRemoveTrailingHyphens -inputString "vm-win-${SUFFIX}" -maxLength 15
$VM_USER_PASSWORD_KV_SECRET_NAME = "${VM_NAME}-password"
AddLog "Variables values set"


# 1. Create Resource Group
az group create --name $RG_NAME --location $LOC
AddLog "Resource Groups created: $RG_NAME."

# 2. Create VNet and subnets
az network vnet create --resource-group $RG_NAME --name $VNET_NAME --location $LOC --address-prefixes $VNET_ADDRESS_PREFIX --subnet-name $WKLD_SUBNET_NAME --subnet-prefix $WKLD_SUBNET_ADDRESS_PREFIX
az network vnet subnet create --resource-group $RG_NAME --vnet-name $VNET_NAME --name AzureFirewallSubnet --address-prefix $AZFW_SUBNET_PREFIX
az network vnet subnet create --resource-group $RG_NAME --vnet-name $VNET_NAME --name AzureFirewallManagementSubnet --address-prefix $AZFW_MGMT_SUBNET_PREFIX
az network vnet subnet create --resource-group $RG_NAME --vnet-name $VNET_NAME --name AzureBastionSubnet --address-prefix $BASTION_SUBNET_ADDRESS_PREFIX
AddLog "VNet and its subnets created: $VNET_NAME"

# 3. Create Azure Firewall
az network public-ip create --resource-group $RG_NAME -n $AZFW_PUBLICIP_NAME --location $LOC --sku "Standard"
az extension add --name azure-firewall
az network firewall create --resource-group $RG_NAME --name $AZFW_NAME --location $LOC --enable-dns-proxy true
az network firewall ip-config create --resource-group $RG_NAME --firewall-name $AZFW_NAME --name $AZFW_IPCONFIG_NAME --public-ip-address $AZFW_PUBLICIP_NAME --vnet-name $VNET_NAME
AddLog "Azure Firewall created: $AZFW_NAME"

$AZFW_PUBLIC_IP = $(az network public-ip show --resource-group $RG_NAME --name $AZFW_PUBLICIP_NAME --query "ipAddress" -o tsv)
$AZFW_PRIVATE_IP = $(az network firewall show --resource-group $RG_NAME --name $AZFW_NAME --query "ipConfigurations[0].privateIPAddress" -o tsv)

# 4. Create UDR to Azure Firewall
az network route-table create --resource-group $RG_NAME --location $LOC --name $AZFW_ROUTE_TABLE_NAME
az network route-table route create --resource-group $RG_NAME --name $AZFW_ROUTE_NAME --route-table-name $AZFW_ROUTE_TABLE_NAME --address-prefix 0.0.0.0/0 --next-hop-type VirtualAppliance --next-hop-ip-address $AZFW_PRIVATE_IP
az network route-table route create --resource-group $RG_NAME --name $AZFW_ROUTE_NAME_INTERNET --route-table-name $AZFW_ROUTE_TABLE_NAME --address-prefix $AZFW_PUBLIC_IP/32 --next-hop-type Internet
AddLog "Route table created: $AZFW_ROUTE_TABLE_NAME"

# 5. Add Azure Firewall rules
# ## for AKS
# az network firewall network-rule create --resource-group $RG_NAME --firewall-name $AZFW_NAME --collection-name 'NetwRC-Aks-AzFw' --name 'NetwR-api-udp' --protocols 'UDP' --source-addresses '*' --destination-addresses "AzureCloud.$LOC" --destination-ports 1194 --action allow --priority 110
# az network firewall network-rule create --resource-group $RG_NAME --firewall-name $AZFW_NAME --collection-name 'NetwRC-Aks-AzFw' --name 'NetwR-api-tcp' --protocols 'TCP' --source-addresses '*' --destination-addresses "AzureCloud.$LOC" --destination-ports 9000
# az network firewall network-rule create --resource-group $RG_NAME --firewall-name $AZFW_NAME --collection-name 'NetwRC-Aks-AzFw' --name 'NetwR-time' --protocols 'UDP' --source-addresses '*' --destination-fqdns 'ntp.ubuntu.com' --destination-ports 123
# az network firewall network-rule create --resource-group $RG_NAME --firewall-name $AZFW_NAME --collection-name 'NetwRC-Aks-AzFw' --name 'NetwR-ghcr' --protocols 'TCP' --source-addresses '*' --destination-fqdns ghcr.io pkg-containers.githubusercontent.com --destination-ports '443'
# az network firewall network-rule create --resource-group $RG_NAME --firewall-name $AZFW_NAME --collection-name 'NetwRC-Aks-AzFw' --name 'NetwR-docker' --protocols 'TCP' --source-addresses '*' --destination-fqdns docker.io registry-1.docker.io production.cloudflare.docker.com --destination-ports '443'
# az network firewall application-rule create --resource-group $RG_NAME --firewall-name $AZFW_NAME --collection-name 'AppRC-Aks-Fw' --name 'AppR-fqdn' --source-addresses '*' --protocols 'http=80' 'https=443' --fqdn-tags "AzureKubernetesService" --action allow --priority 110
# AddLog "Azure Firewall rules created for AKS"

## General Internet access rules
az network firewall application-rule create --resource-group $RG_NAME --firewall-name $AZFW_NAME --collection-name 'AppRC-Allow-All-HttpHttps' --name 'AppR-Allow-Http' --source-addresses $VNET_ADDRESS_PREFIX --protocols 'http=80' --target-fqdns '*' --action allow --priority 100
az network firewall application-rule create --resource-group $RG_NAME --firewall-name $AZFW_NAME --collection-name 'AppRC-Allow-All-HttpHttps' --name 'AppR-Allow-Https' --source-addresses $VNET_ADDRESS_PREFIX --protocols 'https=443' --target-fqdns '*'
AddLog "Azure Firewall rules created for Allow All Http + Https outbound"

# 6. Associate UDR to AKS subnet
az network vnet subnet update --resource-group $RG_NAME --vnet-name $VNET_NAME --name $WKLD_SUBNET_NAME --route-table $AZFW_ROUTE_TABLE_NAME
AddLog "Route table associated to AKS subnet: $WKLD_SUBNET_NAME"

# 7. Create Log Analytics Workspace & Storage account for logs
az monitor log-analytics workspace create --name $LAW_NAME --resource-group $RG_NAME --sku "PerGB2018" --location $LOC
AddLog "Log Analytics Workspace created: $LAW_NAME"
az storage account create --name $ST_NAME --resource-group $RG_NAME --location $LOC --sku Standard_LRS `
  --allow-blob-public-access false `
  --public-network-access Disabled `
  --default-action Deny `
  --min-tls-version TLS1_2
AddLog "Storage Account created: $ST_NAME"

# 8. Enable diagnostic settings for Azure Firewall
$LAW_ID = $(az monitor log-analytics workspace show --resource-group $RG_NAME --workspace-name $LAW_NAME --query id -o tsv)
$AZFW_ID = $(az network firewall show --resource-group $RG_NAME --name $AZFW_NAME --query id -o tsv)
$ST_ID = $(az storage account show --resource-group $RG_NAME --name $ST_NAME --query id -o tsv)

# Create diagnostic settings for Azure Firewall - Enable all Log categories
$diagnosticLogs = @(
  @{category = "AZFWApplicationRule"; enabled = $true }
  @{category = "AZFWApplicationRuleAggregation"; enabled = $true }
  @{category = "AZFWNatRule"; enabled = $true }
  @{category = "AZFWNatRuleAggregation"; enabled = $true }
  @{category = "AZFWNetworkRule"; enabled = $true }
  @{category = "AZFWNetworkRuleAggregation"; enabled = $true }
  @{category = "AZFWDnsQuery"; enabled = $true }
  @{category = "AZFWFqdnResolveFailure"; enabled = $true }
  @{category = "AZFWFatFlow"; enabled = $true }
  @{category = "AZFWFlowTrace"; enabled = $true }
  @{category = "AZFWIdpsSignature"; enabled = $true }
  @{category = "AZFWThreatIntel"; enabled = $true }
) | ConvertTo-Json -Compress

az monitor diagnostic-settings create --name "diag-law-${AZFW_NAME}" `
  --resource $AZFW_ID `
  --workspace $LAW_ID `
  --export-to-resource-specific true `
  --logs $diagnosticLogs

az monitor diagnostic-settings create --name "diag-st-${AZFW_NAME}" `
  --resource $AZFW_ID `
  --storage-account $ST_ID `
  --logs $diagnosticLogs
AddLog "Diagnostic settings created for Azure Firewall: $AZFW_NAME"


# 9. Create Azure Bastion
az network public-ip create `
  --resource-group $RG_NAME `
  --name $BASTION_PIP_NAME `
  --location $LOC `
  --sku Standard

az network bastion create `
  --name $BASTION_NAME `
  --public-ip-address $BASTION_PIP_NAME `
  --resource-group $RG_NAME `
  --vnet-name $VNET_NAME `
  --location $LOC `
  --sku Basic


# 10. Create Private DNS Zones
$privateDnsZones = @(
  @{
    name         = "privatelink.vaultcore.azure.net"
    linkName     = "kv-privdns-vnet-link"
    resourceType = "Key Vault"
  },
  @{
    name         = "privatelink.api.azureml.ms"
    linkName     = "az-ml-privdns-vnet-link"
    resourceType = "Azure Machine Learning Workspace"
  },
  @{
    name         = "privatelink.notebooks.azure.net"
    linkName     = "az-ml-nb-privdns-vnet-link"
    resourceType = "Azure Machine Learning Notebooks"
  },
  @{
    name         = "privatelink.blob.core.windows.net"
    linkName     = "st-blob-privdns-vnet-link"
    resourceType = "Storage Account Blob"
  }
)

foreach ($zone in $privateDnsZones) {
  # Create Private DNS Zone
  az network private-dns zone create `
    --name $zone.name `
    --resource-group $RG_NAME
  AddLog "Private DNS Zone created for $($zone.resourceType)"

  # Create VNet Link
  az network private-dns link vnet create `
    --name $zone.linkName `
    --resource-group $RG_NAME `
    --zone-name $zone.name `
    --virtual-network $VNET_NAME `
    --registration-enabled false
  AddLog "Private DNS Zone linked to VNet for $($zone.resourceType)"
}


# 11. Create Azure Key Vault
$MY_PUBLIC_IP = $((Invoke-WebRequest ifconfig.me/ip).Content.Trim())
az keyvault create --name $KV_NAME --resource-group $RG_NAME --location $LOC `
  --enabled-for-deployment false `
  --enabled-for-template-deployment false `
  --enabled-for-disk-encryption true `
  --bypass 'AzureServices' `
  --network-acls-ips $MY_PUBLIC_IP/32 `
  --default-action 'Deny' `
  --public-network-access Enabled
AddLog "Key Vault created: $KV_NAME"


# 12. Create a Windows VM
# Create VM admin Password
$VM_USER_PASSWORD = GeneratePassword 18
az keyvault secret set --vault-name $KV_NAME --name $VM_USER_PASSWORD_KV_SECRET_NAME --value $VM_USER_PASSWORD
AddLog "Key Vault secret created: $VM_USER_PASSWORD_KV_SECRET_NAME"

# Create the Windows 11 VM
$WKLD_SUBNET_ID = $(az network vnet subnet show --resource-group $RG_NAME --vnet-name $VNET_NAME --name $WKLD_SUBNET_NAME --query id -o tsv)
az vm create `
  --resource-group $RG_NAME `
  --name $VM_NAME `
  --image "microsoftwindowsdesktop:windows-11:win11-24h2-pro:latest" `
  --public-ip-address '""' `
  --size "Standard_F16s_v2" `
  --subnet $WKLD_SUBNET_ID `
  --admin-username $VM_USER_NAME `
  --admin-password $VM_USER_PASSWORD
AddLog "Windows VM created: $VM_NAME"

# 11. Create Azure Firewall rules for VM
$VM_PRIVATE_NIC_ID = $(az vm show --resource-group $RG_NAME --name $VM_NAME --query "networkProfile.networkInterfaces[0].id" -o tsv)
$VM_PRIVATE_IP = $(az network nic show --ids $VM_PRIVATE_NIC_ID --query "ipConfigurations[0].privateIPAddress" -o tsv)

# Allow VM inbound access from Public internet to internal RDP through DNAT
az network firewall nat-rule create `
  --resource-group $RG_NAME `
  --firewall-name $AZFW_NAME `
  --collection-name 'NatRC-rdp' `
  --name 'NatR-vm-win11' `
  --destination-addresses $AZFW_PUBLIC_IP `
  --destination-ports $VM_PUBLIC_PORT `
  --protocols Any `
  --source-addresses $MY_PUBLIC_IP `
  --translated-port 3389 `
  --action Dnat `
  --priority 120 `
  --translated-address $VM_PRIVATE_IP

# Allow VM outbound access to Public internet
az network firewall network-rule create `
  --resource-group $RG_NAME `
  --firewall-name $AZFW_NAME `
  --collection-name 'NetwRC-vm-win11' `
  --name 'NetwR-allow-all-out' `
  --protocols 'Any' `
  --source-addresses $VM_PRIVATE_IP `
  --destination-addresses "*" `
  --destination-ports "*" `
  --action allow `
  --priority 120
AddLog "Azure Firewall rules created for VM: $VM_NAME"


# 13. Create Azure Container Registry
az acr create --resource-group $RG_NAME --name $ACR_NAME `
  --sku Premium `
  --location $LOC `
  --admin-enabled false `
  --public-network-enabled false `
  --default-action Deny `
  --allow-trusted-services true
AddLog "Container Registry created: $ACR_NAME"


# 13. Create Private Endpoints
# Key Vault private endpoint
$KV_ID = $(az keyvault show --name $KV_NAME --resource-group $RG_NAME --query id -o tsv)
CreatePrivateEndpoint -name $KV_NAME `
  -resourceId $KV_ID `
  -groupId "vault" `
  -dnsZoneName "privatelink.vaultcore.azure.net" `
  -rgName $RG_NAME `
  -vnetName $VNET_NAME `
  -subnetName $WKLD_SUBNET_NAME

# Storage Account private endpoint
$ST_ID = $(az storage account show --name $ST_NAME --resource-group $RG_NAME --query id -o tsv)
CreatePrivateEndpoint -name $ST_NAME `
  -resourceId $ST_ID `
  -groupId "blob" `
  -dnsZoneName "privatelink.blob.core.windows.net" `
  -resourceType "Storage Account Blob" `
  -rgName $RG_NAME `
  -vnetName $VNET_NAME `
  -subnetName $WKLD_SUBNET_NAME `
  -suffix $SUFFIX


# 14. Create Application Insights
az monitor app-insights component create `
  --app $APP_INS_NAME `
  --resource-group $RG_NAME `
  --location $LOC `
  --kind web `
  --application-type web `
  --workspace $LAW_ID
AddLog "Application Insights created: $APP_INS_NAME"


# 15. Create Azure Machine Learning Workspace
az extension add -n ml # az extension update -n ml

$KV_ID = $(az keyvault show --name $KV_NAME --resource-group $RG_NAME --query id -o tsv)
$ACR_ID = $(az acr show --name $ACR_NAME --resource-group $RG_NAME --query id -o tsv)
$APP_INS_ID = $(az monitor app-insights component show --app $APP_INS_NAME --resource-group $RG_NAME --query id -o tsv)

# Create the workspace using Azure CLI
az ml workspace create -g $RG_NAME `
  --name $AML_WS_NAME `
  --description "Private Azure Machine Learning Workspace" `
  --location $LOC `
  --storage-account $ST_ID `
  --key-vault $KV_ID `
  --application-insights $APP_INS_ID `
  --container-registry $ACR_ID `
  --public-network-access Disabled `
  --system-datastores-auth-mode identity `
  --managed-network 'allow_only_approved_outbound'
AddLog "Azure Machine Learning Workspace created using configuration: $AML_WS_NAME"

# Create the Private Endpoint for the Azure Machine Learning Workspace
$AML_WS_ID = $(az ml workspace show --name $AML_WS_NAME --resource-group $RG_NAME --query id -o tsv)
az network private-endpoint create `
  --name "$AML_WS_NAME-pe" `
  --resource-group $RG_NAME `
  --vnet-name $VNET_NAME `
  --subnet $WKLD_SUBNET_NAME `
  --private-connection-resource-id $AML_WS_ID `
  --group-id 'amlworkspace' `
  --connection-name "$AML_WS_NAME-pe-conn" `
  --nic-name "$AML_WS_NAME-pe-nic"

az network private-endpoint dns-zone-group create `
  -g $RG_NAME `
  --endpoint-name "$AML_WS_NAME-pe" `
  --name 'zone-group' `
  --private-dns-zone 'privatelink.api.azureml.ms' `
  --zone-name 'privatelink.api.azureml.ms'

az network private-endpoint dns-zone-group add `
  -g $RG_NAME `
  --endpoint-name "$AML_WS_NAME-pe" `
  --name 'zone-group' `
  --private-dns-zone 'privatelink.notebooks.azure.net' `
  --zone-name 'privatelink.notebooks.azure.net'


# Create required User-assigned managed identity for Private compute instances
$AML_UAI_NAME = "$AML_WS_NAME-uai"
az identity create --name $AML_UAI_NAME --resource-group $RG_NAME --location $LOC
# $AML_UAI_ID = $(az identity show --name $AML_UAI_NAME --resource-group $RG_NAME --query id -o tsv)
# $AML_UAI_PRINCIPAL_ID = $(az identity show --name $AML_UAI_NAME --resource-group $RG_NAME --query principalId -o tsv)
# $AML_UAI_CLIENT_ID = $(az identity show --name $AML_UAI_NAME --resource-group $RG_NAME --query clientId -o tsv)
AddLog "User-assigned managed identity created: $AML_UAI_NAME"

# # Grant the user-assigned managed identity Contributor access to the AML workspace
# $AML_WS_SCOPE = $(az ml workspace show --name $AML_WS_NAME --resource-group $RG_NAME --query id -o tsv)
# az role assignment create --assignee-object-id $AML_UAI_PRINCIPAL_ID --role "Contributor" --scope $AML_WS_SCOPE
# AddLog "Granted Contributor role to UAI on AML workspace"

# # Grant the user-assigned managed identity access to Key Vault secrets
# az keyvault set-policy --name $KV_NAME `
#   --object-id $AML_UAI_PRINCIPAL_ID `
#   --secret-permissions get list `
#   --key-permissions get list `
#   --certificate-permissions get list
# AddLog "Granted Key Vault access policies to UAI"


# 16. Create Azure Container Apps + App Service + Function App

