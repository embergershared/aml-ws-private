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
    [int]$maxLength,

    [Parameter(Mandatory = $false)]
    [switch]$Randomize
  )

  # First trim the string to the maximum length, leaving room for random numbers if needed
  $effectiveMaxLength = if ($Randomize) { $maxLength - 4 } else { $maxLength }
  $trimmedString = $inputString.Substring(0, [System.Math]::Min($effectiveMaxLength, $inputString.Length))
    
  # Remove any trailing hyphens
  $trimmedString = $trimmedString.TrimEnd('-')
    
  # Remove any leading hyphens
  $trimmedString = $trimmedString.TrimStart('-')

  # Add random numbers if specified
  if ($Randomize) {
    $randomNum = -join ((Get-Random -Minimum 111 -Maximum 999).ToString())
    $trimmedString = "${trimmedString}-${randomNum}"
  }
    
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
$VNET_NAME = TrimAndRemoveTrailingHyphens -inputString "vnet-${SUFFIX}" -maxLength 64
$VNET_ADDRESS_PREFIX = "192.168.42.0/23"

$WKLD_SUBNET_NAME = "wkld-snet"
$WKLD_SUBNET_ADDRESS_PREFIX = "192.168.43.0/25"

$AZFW_NAME = TrimAndRemoveTrailingHyphens -inputString "azfw-${SUFFIX}" -maxLength 64
$AZFW_SUBNET_PREFIX = "192.168.42.0/26"
$AZFW_MGMT_SUBNET_PREFIX = "192.168.42.64/26"
$AZFW_PUBLICIP_NAME = "${AZFW_NAME}-pip"
$AZFW_ROUTE_TABLE_NAME = TrimAndRemoveTrailingHyphens -inputString "udr-${SUFFIX}" -maxLength 64
$AZFW_ROUTE_NAME = "next-hop-v-appliance-to-azfw-private-ip"
$AZFW_ROUTE_NAME_INTERNET = "next-hop-internet-to-azfw-public-ip"

$BASTION_NAME = TrimAndRemoveTrailingHyphens -inputString "bastion-${SUFFIX}" -maxLength 64
$BASTION_PIP_NAME = "${BASTION_NAME}-pip"
$BASTION_SUBNET_ADDRESS_PREFIX = "192.168.42.128/26"

$KV_NAME = TrimAndRemoveTrailingHyphens -inputString "kv-${SUFFIX}" -maxLength 24
$LAW_NAME = TrimAndRemoveTrailingHyphens -inputString "law-${SUFFIX}" -maxLength 15
$ST_NAME = (TrimAndRemoveTrailingHyphens -inputString "st-${SUFFIX}" -maxLength 24).Replace("-", "").ToLower()
$APP_INS_NAME = TrimAndRemoveTrailingHyphens -inputString "appi-${SUFFIX}" -maxLength 260
$ACR_NAME = (TrimAndRemoveTrailingHyphens -inputString "acr-${SUFFIX}" -maxLength 24).Replace("-", "").ToLower()
$AML_WS_NAME = TrimAndRemoveTrailingHyphens -inputString "amlws-${SUFFIX}" -maxLength 24

$VM_NAME = TrimAndRemoveTrailingHyphens -inputString "vm-win-${SUFFIX}" -maxLength 15
$VM_USER_PASSWORD_KV_SECRET_NAME = "${VM_NAME}-password"

$ACA_ENV_NAME = TrimAndRemoveTrailingHyphens -inputString "aca-env-${SUFFIX}" -maxLength 32
$ACA_ENV_SUBNET_NAME = "aca-env-snet"
$ACA_ENV_SUBNET_ADDRESS_PREFIX = "192.168.42.192/26"
$ACA_APP_NAME = TrimAndRemoveTrailingHyphens -inputString "aca-app-sample-${SUFFIX}" -maxLength 32
$ACA_APP_UAI_NAME = "$ACA_APP_NAME-uai"
$ACA_SUBNET_NAME = "aca-snet"
$ACA_SUBNET_ADDRESS_PREFIX = "192.168.43.128/26"

$APP_SVC_PLAN_NAME = TrimAndRemoveTrailingHyphens -inputString "appsvc-plan-${SUFFIX}" -maxLength 32
$APP_SVC_ST_NAME = (TrimAndRemoveTrailingHyphens -inputString "st-appsvc-${SUFFIX}" -maxLength 24).Replace("-", "").ToLower()
$FUNC_APP_NAME = TrimAndRemoveTrailingHyphens -inputString "appsvc-func-app-${SUFFIX}" -maxLength 32

AddLog "Variables values set"


# 1. Create Resource Group
az group create --name $RG_NAME --location $LOC
AddLog "Resource Groups created: $RG_NAME."

# 2. Create VNet and subnets
az network vnet create `
  --resource-group $RG_NAME `
  --name $VNET_NAME `
  --location $LOC `
  --address-prefixes $VNET_ADDRESS_PREFIX `
  --subnet-name $WKLD_SUBNET_NAME `
  --subnet-prefix $WKLD_SUBNET_ADDRESS_PREFIX

az network vnet subnet create `
  --resource-group $RG_NAME `
  --vnet-name $VNET_NAME `
  --name AzureFirewallSubnet `
  --address-prefix $AZFW_SUBNET_PREFIX

az network vnet subnet create `
  --resource-group $RG_NAME `
  --vnet-name $VNET_NAME `
  --name AzureFirewallManagementSubnet `
  --address-prefix $AZFW_MGMT_SUBNET_PREFIX

az network vnet subnet create `
  --resource-group $RG_NAME `
  --vnet-name $VNET_NAME `
  --name AzureBastionSubnet `
  --address-prefix $BASTION_SUBNET_ADDRESS_PREFIX

az network vnet subnet create `
  --resource-group $RG_NAME `
  --vnet-name $VNET_NAME `
  --name $ACA_SUBNET_NAME `
  --address-prefix $ACA_SUBNET_ADDRESS_PREFIX
AddLog "VNet and its subnets created: $VNET_NAME"


# 3. Create Azure Firewall
az network public-ip create `
  --resource-group $RG_NAME `
  -n $AZFW_PUBLICIP_NAME `
  --location $LOC `
  --sku "Standard"

# az extension add --name azure-firewall
az network firewall create `
  --resource-group $RG_NAME `
  --name $AZFW_NAME `
  --location $LOC `
  --enable-dns-proxy true
AddLog "Azure Firewall created: $AZFW_NAME"

az network firewall ip-config create `
  --resource-group $RG_NAME `
  --firewall-name $AZFW_NAME `
  --name "pip-ipconfig" `
  --public-ip-address $AZFW_PUBLICIP_NAME `
  --vnet-name $VNET_NAME
AddLog "Azure Firewall Public IP configuration created."


# 4. Create UDR to Azure Firewall
$AZFW_PUBLIC_IP = $(az network public-ip show --resource-group $RG_NAME --name $AZFW_PUBLICIP_NAME --query "ipAddress" -o tsv)
$AZFW_PRIVATE_IP = $(az network firewall show --resource-group $RG_NAME --name $AZFW_NAME --query "ipConfigurations[0].privateIPAddress" -o tsv)

az network route-table create `
  --resource-group $RG_NAME `
  --location $LOC `
  --name $AZFW_ROUTE_TABLE_NAME

az network route-table route create `
  --resource-group $RG_NAME `
  --name $AZFW_ROUTE_NAME `
  --route-table-name $AZFW_ROUTE_TABLE_NAME `
  --address-prefix 0.0.0.0/0 `
  --next-hop-type VirtualAppliance `
  --next-hop-ip-address $AZFW_PRIVATE_IP

az network route-table route create `
  --resource-group $RG_NAME `
  --name $AZFW_ROUTE_NAME_INTERNET `
  --route-table-name $AZFW_ROUTE_TABLE_NAME `
  --address-prefix $AZFW_PUBLIC_IP/32 `
  --next-hop-type Internet
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
az network firewall application-rule create `
  --resource-group $RG_NAME `
  --firewall-name $AZFW_NAME `
  --collection-name 'AppRC-Allow-All-HttpHttps' `
  --name 'AppR-Allow-Http' `
  --source-addresses $VNET_ADDRESS_PREFIX `
  --protocols 'http=80' `
  --target-fqdns '*' `
  --action allow `
  --priority 100

az network firewall application-rule create `
  --resource-group $RG_NAME `
  --firewall-name $AZFW_NAME `
  --collection-name 'AppRC-Allow-All-HttpHttps' `
  --name 'AppR-Allow-Https' `
  --source-addresses $VNET_ADDRESS_PREFIX `
  --protocols 'https=443' `
  --target-fqdns '*'
AddLog "Azure Firewall rules created for Allow All Http + Https outbound"

# 6. Associate UDR to AKS subnet
az network vnet subnet update `
  --resource-group $RG_NAME `
  --vnet-name $VNET_NAME `
  --name $WKLD_SUBNET_NAME `
  --route-table $AZFW_ROUTE_TABLE_NAME

az network vnet subnet update `
  --resource-group $RG_NAME `
  --vnet-name $VNET_NAME `
  --name $ACA_SUBNET_NAME `
  --route-table $AZFW_ROUTE_TABLE_NAME `
  --delegations Microsoft.Web/serverFarms

AddLog "Route table associated to Workloads subnets: $WKLD_SUBNET_NAME & $ACA_SUBNET_NAME."

# 7. Create Log Analytics Workspace & Storage account for logs
az monitor log-analytics workspace create `
  --name $LAW_NAME `
  --resource-group $RG_NAME `
  --sku "PerGB2018" `
  --location $LOC
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
# az network public-ip create `
#   --resource-group $RG_NAME `
#   --name $BASTION_PIP_NAME `
#   --location $LOC `
#   --sku Standard

# az network bastion create `
#   --name $BASTION_NAME `
#   --public-ip-address $BASTION_PIP_NAME `
#   --resource-group $RG_NAME `
#   --vnet-name $VNET_NAME `
#   --location $LOC `
#   --sku Basic


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
  AddLog "Private DNS Zone created for: $($zone.resourceType)"

  # Create VNet Link
  az network private-dns link vnet create `
    --name $zone.linkName `
    --resource-group $RG_NAME `
    --zone-name $zone.name `
    --virtual-network $VNET_NAME `
    --registration-enabled false
  AddLog "Private DNS Zone linked to VNet for: $($zone.resourceType)"
}


# 11. Create Azure Key Vault
$MY_PUBLIC_IP = $((Invoke-WebRequest ifconfig.me/ip).Content.Trim())
az keyvault create `
  --name $KV_NAME `
  --resource-group $RG_NAME `
  --location $LOC `
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
az keyvault secret set `
  --vault-name $KV_NAME `
  --name $VM_USER_PASSWORD_KV_SECRET_NAME `
  --value $VM_USER_PASSWORD
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


# 12. Create Azure Container Registry
az acr create `
  --resource-group $RG_NAME `
  --name $ACR_NAME `
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
CreatePrivateEndpoint `
  -name $KV_NAME `
  -resourceId $KV_ID `
  -groupId "vault" `
  -dnsZoneName "privatelink.vaultcore.azure.net" `
  -rgName $RG_NAME `
  -vnetName $VNET_NAME `
  -subnetName $WKLD_SUBNET_NAME

# Storage Account private endpoint
$ST_ID = $(az storage account show --name $ST_NAME --resource-group $RG_NAME --query id -o tsv)
CreatePrivateEndpoint `
  -name $ST_NAME `
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
az ml workspace create `
  -g $RG_NAME `
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
AddLog "Azure Machine Learning Workspace created: $AML_WS_NAME"

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


# Create required User-assigned managed identity for Private Compute instances
$AML_UAI_NAME = "$AML_WS_NAME-uai"
az identity create --name $AML_UAI_NAME --resource-group $RG_NAME --location $LOC
AddLog "User-assigned managed identity created: $AML_UAI_NAME"


# Assign required roles to the User-assigned managed identity
# Ref: https://learn.microsoft.com/en-us/azure/machine-learning/how-to-disable-local-auth-storage?view=azureml-api-2&tabs=portal#scenarios-for-role-assignments

# $AML_UAI_ID = $(az identity show --name $AML_UAI_NAME --resource-group $RG_NAME --query id -o tsv)
$AML_UAI_PRINCIPAL_ID = $(az identity show --name $AML_UAI_NAME --resource-group $RG_NAME --query principalId -o tsv)
# $AML_UAI_CLIENT_ID = $(az identity show --name $AML_UAI_NAME --resource-group $RG_NAME --query clientId -o tsv)

# Grant the user-assigned managed identity Reader access to the resource group
az role assignment create `
  --assignee-object-id $AML_UAI_PRINCIPAL_ID `
  --role "Storage Blob Data Contributor" `
  --scope $ST_ID

az role assignment create `
  --assignee-object-id $AML_UAI_PRINCIPAL_ID `
  --role "Storage File Data Privileged Contributor" `
  --scope $ST_ID
AddLog "Role Assignments created for Azure ML Studio User-assigned managed identity: $AML_UAI_NAME"


# 16. Create Azure Container Apps
# Container Apps Environment => Subnet
az network vnet subnet create `
  --name $ACA_ENV_SUBNET_NAME `
  --resource-group $RG_NAME `
  --vnet-name $VNET_NAME `
  --address-prefixes $ACA_ENV_SUBNET_ADDRESS_PREFIX

az network vnet subnet update `
  --name $ACA_ENV_SUBNET_NAME `
  --resource-group $RG_NAME `
  --vnet-name $VNET_NAME `
  --delegations Microsoft.App/environments `
  --route-table $AZFW_ROUTE_TABLE_NAME
AddLog "Container App subnet created and updated: $ACA_ENV_SUBNET_NAME"

# Container Apps Environment => Environment
$ACA_ENV_SUBNET_ID = $(az network vnet subnet show --resource-group $RG_NAME --vnet-name $VNET_NAME --name $ACA_ENV_SUBNET_NAME --query id -o tsv)
$LOG_ANALYTICS_WORKSPACE_CLIENT_ID = $(az monitor log-analytics workspace show --resource-group $RG_NAME --workspace-name $LAW_NAME --query customerId -o tsv)
$LOG_ANALYTICS_WORKSPACE_CLIENT_SECRET = $(az monitor log-analytics workspace get-shared-keys --resource-group $RG_NAME --workspace-name $LAW_NAME --query primarySharedKey -o tsv)

az containerapp env create `
  --name $ACA_ENV_NAME `
  --resource-group $RG_NAME `
  --location $LOC `
  --infrastructure-subnet-resource-id $ACA_ENV_SUBNET_ID `
  --logs-workspace-id $LOG_ANALYTICS_WORKSPACE_CLIENT_ID `
  --logs-workspace-key $LOG_ANALYTICS_WORKSPACE_CLIENT_SECRET `
  --internal-only true
AddLog "Container Apps Environment created: $ACA_ENV_NAME"


# Container Apps Sample Application
az identity create --name $ACA_APP_UAI_NAME --resource-group $RG_NAME --location $LOC
AddLog "User-assigned managed identity created: $ACA_APP_UAI_NAME"

$ACA_APP_UAI_ID = $(az identity show --name $ACA_APP_UAI_NAME --resource-group $RG_NAME --query id -o tsv)
$ACA_ENV_ID = $(az containerapp env show --name $ACA_ENV_NAME --resource-group $RG_NAME --query id -o tsv)
$ACR_FQDN = $(az acr show --name $ACR_NAME --resource-group $RG_NAME --query loginServer -o tsv)

az containerapp create `
  --name $ACA_APP_NAME `
  --resource-group $RG_NAME `
  --environment $ACA_ENV_NAME `
  --registry-server $ACR_FQDN `
  --registry-identity 'system' `
  --image mcr.microsoft.com/azuredocs/containerapps-helloworld:latest `
  --target-port 80 `
  --ingress external `
  --min-replicas 1 `
  --max-replicas 2 `
  --env-vars "MESSAGE=Hello from private Container Apps!" `
  --user-assigned $ACA_APP_UAI_ID `
  --query properties.configuration.ingress.fqdn
AddLog "Container App created: $ACA_APP_NAME"

# Create private DNS zone for Container Apps
$privateDnsZoneContainerApps = @(
  @{
    name         = "privatelink.azurecontainerapps.io"
    linkName     = "aca-privdns-vnet-link"
    resourceType = "Azure Container Apps"
  }
)

foreach ($zone in $privateDnsZoneContainerApps) {
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

# Create private endpoint for Container Apps Environment
CreatePrivateEndpoint `
  -name $ACA_ENV_NAME `
  -resourceId $ACA_ENV_ID `
  -groupId "managedEnvironments" `
  -dnsZoneName "privatelink.azurecontainerapps.io" `
  -rgName $RG_NAME `
  -vnetName $VNET_NAME `
  -subnetName $WKLD_SUBNET_NAME


# 17. App Service Plan + Function App
# Create App Service Plan
az appservice plan create `
  --name $APP_SVC_PLAN_NAME `
  --resource-group $RG_NAME `
  --location $LOC `
  --sku P1v3 `
  --is-linux
AddLog "App Service Plan created: $APP_SVC_PLAN_NAME"

az storage account create --name $APP_SVC_ST_NAME --resource-group $RG_NAME --location $LOC --sku Standard_LRS `
  --allow-blob-public-access false `
  --public-network-access Disabled `
  --default-action Deny `
  --min-tls-version TLS1_2

$APP_SVC_ST_ID = $(az storage account show --name $APP_SVC_ST_NAME --resource-group $RG_NAME --query id -o tsv)
CreatePrivateEndpoint `
  -name $APP_SVC_ST_NAME `
  -resourceId $APP_SVC_ST_ID `
  -groupId "blob" `
  -dnsZoneName "privatelink.blob.core.windows.net" `
  -rgName $RG_NAME `
  -vnetName $VNET_NAME `
  -subnetName $WKLD_SUBNET_NAME


# Create Function App with .NET 8 runtime
$ACA_SUBNET_ID = $(az network vnet subnet show --resource-group $RG_NAME --vnet-name $VNET_NAME --name $ACA_SUBNET_NAME --query id -o tsv)
az functionapp create `
  --name $FUNC_APP_NAME `
  --resource-group $RG_NAME `
  --storage-account $APP_SVC_ST_NAME `
  --plan $APP_SVC_PLAN_NAME `
  --runtime dotnet-isolated `
  --runtime-version 8 `
  --functions-version 4 `
  --app-insights $APP_INS_NAME `
  --assign-identity "[system]" `
  --vnet $VNET_NAME `
  --subnet $ACA_SUBNET_NAME
AddLog "Function App created: $FUNC_APP_NAME"

# Configure Function App settings
az functionapp config appsettings set `
  --name $FUNC_APP_NAME `
  --resource-group $RG_NAME `
  --settings "WEBSITE_CONTENTOVERVNET=1" "WEBSITE_VNET_ROUTE_ALL=1" "WEBSITE_DNS_SERVER=168.63.129.16"
AddLog "Function App settings configured for VNET integration"

# Create private DNS zone for Function App
$privateDnsZoneFunctionApp = @(
  @{
    name         = "privatelink.azurewebsites.net"
    linkName     = "func-privdns-vnet-link"
    resourceType = "Azure Function App"
  }
)

foreach ($zone in $privateDnsZoneFunctionApp) {
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

# Create private endpoint for Function App
$FUNC_ID = $(az functionapp show --name $FUNC_APP_NAME --resource-group $RG_NAME --query id -o tsv)
CreatePrivateEndpoint -name $FUNC_APP_NAME `
  -resourceId $FUNC_ID `
  -groupId "sites" `
  -dnsZoneName "privatelink.azurewebsites.net" `
  -rgName $RG_NAME `
  -vnetName $VNET_NAME `
  -subnetName $WKLD_SUBNET_NAME

# Update Function App networking config to use private endpoints
az functionapp config access-restriction set `
  --name $FUNC_APP_NAME `
  --resource-group $RG_NAME `
  --use-same-restrictions-for-scm-site true
AddLog "Function App private endpoint and access restrictions configured"
