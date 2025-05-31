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
    $password = -join (0..$length | % { $characterList | Get-Random })
    [int]$hasLowerChar = $password -cmatch '[a-z]'
    [int]$hasUpperChar = $password -cmatch '[A-Z]'
    [int]$hasDigit = $password -match '[0-9]'
    [int]$hasSymbol = $password.IndexOfAny($symbols) -ne -1
  }
  until (($hasLowerChar + $hasUpperChar + $hasDigit + $hasSymbol) -ge 3)

  return $password #| ConvertTo-SecureString -AsPlainText
}
AddLog "Functions loaded"

# Sourced variables
. "$PSScriptRoot\azcli-values.ps1"

# Generated variables
$RG_NAME = "rg-${SUFFIX}"
$VNET_NAME = "vnet-${SUFFIX}"
$WKLD_SUBNET_NAME = "wkld-snet"

$AZFW_NAME = "azfw-${SUFFIX}"
$AZFW_PUBLICIP_NAME = "pip-for-azfw-${SUFFIX}"
$AZFW_IPCONFIG_NAME = "azfw-ipconfig-${SUFFIX}"
$AZFW_ROUTE_TABLE_NAME = "udr-${SUFFIX}"
$AZFW_ROUTE_NAME = "azfw-route-${SUFFIX}"
$AZFW_ROUTE_NAME_INTERNET = "azfw-route-internet-${SUFFIX}"

$BASTION_NAME = "bastion-${SUFFIX}"
$BASTION_PIP_NAME = "pip-for-bastion-${SUFFIX}"

$KV_NAME = TrimAndRemoveTrailingHyphens -inputString "kv-${SUFFIX}" -maxLength 24
$LAW_NAME = TrimAndRemoveTrailingHyphens -inputString "law-${SUFFIX}" -maxLength 15
$ST_NAME = (TrimAndRemoveTrailingHyphens -inputString "st-${SUFFIX}" -maxLength 24).Replace("-", "").ToLower()
$APPI_NAME = TrimAndRemoveTrailingHyphens -inputString "appi-${SUFFIX}" -maxLength 260

$VM_NAME = TrimAndRemoveTrailingHyphens -inputString "vm-win-${SUFFIX}" -maxLength 15
$VM_USER_PASSWORD_KV_SECRET_NAME = "${VM_NAME}-password"
AddLog "Variables values set"


# 1. Create Resource Groups
az group create --name $RG_NAME --location $LOC
AddLog "Resource Groups created: $RG_NAME."

# 2. Create VNet and subnets
az network vnet create --resource-group $RG_NAME --name $VNET_NAME --location $LOC --address-prefixes 10.42.0.0/16 --subnet-name $WKLD_SUBNET_NAME --subnet-prefix 10.42.1.0/24
az network vnet subnet create --resource-group $RG_NAME --vnet-name $VNET_NAME --name AzureFirewallSubnet --address-prefix 10.42.0.192/26
az network vnet subnet create --resource-group $RG_NAME --vnet-name $VNET_NAME --name AzureFirewallManagementSubnet --address-prefix 10.42.0.128/26
az network vnet subnet create --resource-group $RG_NAME --vnet-name $VNET_NAME --name AzureBastionSubnet --address-prefix 10.42.0.64/26
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
az network route-table route create --resource-group $RG --name $AZFW_ROUTE_NAME_INTERNET --route-table-name $AZFW_ROUTE_TABLE_NAME --address-prefix $AZFW_PUBLIC_IP/32 --next-hop-type Internet
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

## general internet access
az network firewall application-rule create --resource-group $RG_NAME --firewall-name $AZFW_NAME --collection-name 'AppRC-Allow-All-HttpHttps' --name 'AppR-Allow-Http' --source-addresses '*' --protocols 'http=80' --target-fqdns '*' --action allow --priority 100
az network firewall application-rule create --resource-group $RG_NAME --firewall-name $AZFW_NAME --collection-name 'AppRC-Allow-All-HttpHttps' --name 'AppR-Allow-Https' --source-addresses '*' --protocols 'https=443' --target-fqdns '*'
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

# 9. Create Azure Key Vault
az keyvault create --name $KV_NAME --resource-group $RG_NAME --location $LOC `
  --enabled-for-deployment false `
  --enabled-for-template-deployment false `
  --enabled-for-disk-encryption true `
  --public-network-access Disabled `
  --network-acls '{\"default-action\":\"Deny\"}'
AddLog "Key Vault created: $KV_NAME"

# Create Key Vault Private DNS Zoneand link it to the VNet
az network private-dns zone create --name "privatelink.vaultcore.azure.net" --resource-group $RG_NAME
AddLog "Private DNS Zone created for Key Vault"

az network private-dns link vnet create --name "pdnslink-kv-${SUFFIX}" `
  --resource-group $RG_NAME `
  --zone-name "privatelink.vaultcore.azure.net" `
  --virtual-network $VNET_NAME `
  --registration-enabled false
AddLog "Private DNS Zone linked to VNet: $VNET_NAME"

# Create private endpoint for Key Vault
$KV_ID = $(az keyvault show --name $KV_NAME --resource-group $RG_NAME --query id -o tsv)
az network private-endpoint create `
  --name "pe-kv-${SUFFIX}" `
  --resource-group $RG_NAME `
  --vnet-name $VNET_NAME `
  --subnet $WKLD_SUBNET_NAME `
  --private-connection-resource-id $KV_ID `
  --group-id vault `
  --connection-name "pe-conn-kv-${SUFFIX}"

# Create DNS zone group for automatic DNS registration
az network private-endpoint dns-zone-group create `
  --name "pdzg-kv-${SUFFIX}" `
  --resource-group $RG_NAME `
  --endpoint-name "pe-kv-${SUFFIX}" `
  --private-dns-zone "privatelink.vaultcore.azure.net" `
  --zone-name default
AddLog "Private endpoint created for Key Vault: $KV_NAME"

# Create Storage Account Blob Private DNS Zone and link it to the VNet
az network private-dns zone create --name "privatelink.blob.core.windows.net" --resource-group $RG_NAME
AddLog "Private DNS Zone created for Storage Account Blob"

az network private-dns link vnet create --name "pdnslink-st-blob-${SUFFIX}" `
  --resource-group $RG_NAME `
  --zone-name "privatelink.blob.core.windows.net" `
  --virtual-network $VNET_NAME `
  --registration-enabled false
AddLog "Private DNS Zone linked to VNet for Storage Account Blob"

# Create private endpoint for Storage Account Blob
$ST_ID = $(az storage account show --name $ST_NAME --resource-group $RG_NAME --query id -o tsv)
az network private-endpoint create `
  --name "pe-st-blob-${SUFFIX}" `
  --resource-group $RG_NAME `
  --vnet-name $VNET_NAME `
  --subnet $WKLD_SUBNET_NAME `
  --private-connection-resource-id $ST_ID `
  --group-id blob `
  --connection-name "pe-conn-st-blob-${SUFFIX}"

# Create DNS zone group for automatic DNS registration
az network private-endpoint dns-zone-group create `
  --name "pdzg-st-blob-${SUFFIX}" `
  --resource-group $RG_NAME `
  --endpoint-name "pe-st-blob-${SUFFIX}" `
  --private-dns-zone "privatelink.blob.core.windows.net" `
  --zone-name default
AddLog "Private endpoint created for Storage Account Blob: $ST_NAME"

# Create Application Insights
az monitor app-insights component create `
  --app $APPI_NAME `
  --resource-group $RG_NAME `
  --location $LOC `
  --kind web `
  --application-type web `
  --workspace $LAW_ID
AddLog "Application Insights created: $APPI_NAME"

## Create Azure Machine Learning Workspace

## Create Azure Container Apps + App Service + Function App

