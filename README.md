# Private Azure Machine Learning

Azure Machine Learning Studio Private deployment


## Overview


## Script usage

1. Create a file in the same folder named `azcli-values.ps1`

2. Add the following content to `azcli-values.ps1`:

```powershell
$RG_NAME = "<resource group name>"
$SUFFIX = "<resources suffix you want>"
$LOC = "<location to use code>"
$VM_USER_NAME = "<bogus admin user name>"
$VM_PUBLIC_PORT = "<TCP port for RDP exposure on Public Internet (Reco: between 59,000 and 64,000)>"
```

> Note: replace the `<...>` with your values.

3. Run the deployment script in a PowerShell terminal:

```powershell
az login

.\azcli-deployment.ps1
```

4. Go take a big coffee break
  
  The deployment will take a while (at least 40 minutes).
