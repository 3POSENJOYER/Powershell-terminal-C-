Powershell Terminal (C#) this is just the initial version!!
# Powershell Terminal (C# 8) — README


## Requirements

* **.NET Core 3.1+** (works with .NET 5 / 6 / 7)
* **PowerShell** (Windows PowerShell or PowerShell 7+)
* **.NET desktop development**
* **.Windows Forms Designer**
* **.NuGet Packege**

---

## Quick Start

1. Clone the repository:

```bash
git clone https://github.com/3POSENJOYER/Powershell-terminal-C-.git
cd Powershell-terminal-C-
install NuGet
Install-Package System.Management.Automation
Install-Package Microsoft.PowerShell.SDK
```

2. Build/run:

```bash
dotnet build
dotnet run
```
##  Basic Commands for Testing

###  PowerShell Commands
```powershell
Get-Date
Get-Process
Get-Service
Get-ChildItem

Working with files:
Get-ChildItem C:\
Get-ChildItem .\
New-Item test.txt
Remove-Item test.txt
  

System information:
$PSVersionTable          
Get-ComputerInfo           
Get-Host        

Just commands:
echo "Hello, World!"       
Write-Host "Hello!"      
1+1                        


