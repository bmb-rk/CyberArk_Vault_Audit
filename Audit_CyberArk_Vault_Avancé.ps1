<# 
 ============================================
 CyberArk Vault Audit Script Avancé
 Version    : 1.0
 Auteur     : Abdelaziz-AitBambark
 Description: Audit complet du serveur Vault CyberArk
              avec vérifications de sécurité, performance et conformité
 ============================================ 
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ReportPath = "C:\CyberArk\Audit\Vault_Audit_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\CyberArk\Audit\vault_audit.log",
    
    [Parameter(Mandatory=$false)]
    [switch]$SendEmail,
    
    [Parameter(Mandatory=$false)]
    [string]$SMTPServer = "smtp.company.com",
    
    [Parameter(Mandatory=$false)]
    [string]$EmailTo = "security-team@company.com"
)

# ----------- Initialisation et configuration --------------
$global:AuditResults = @()
$global:ErrorCount = 0
$global:WarningCount = 0

# Création du répertoire de sortie
$OutputDir = Split-Path $ReportPath -Parent
if (!(Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# Fonction de logging
function Write-AuditLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry
    $logEntry | Out-File $LogPath -Append
}

# Fonction d'ajout de résultat d'audit
function Add-AuditResult {
    param(
        [string]$Category,
        [string]$Check,
        [string]$Status,
        [string]$Message,
        [string]$Details = ""
    )
    
    $result = [PSCustomObject]@{
        Category = $Category
        Check = $Check
        Status = $Status
        Message = $Message
        Details = $Details
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    $global:AuditResults += $result
    
    if ($Status -eq "ERROR") { $global:ErrorCount++ }
    if ($Status -eq "WARNING") { $global:WarningCount++ }
    
    Write-AuditLog "[$Status] $Category - $Check: $Message"
}

# Fonction de test de port avancé
function Test-VaultPort {
    param([int]$Port, [string]$Description)
    
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $result = $tcpClient.BeginConnect("localhost", $Port, $null, $null)
        $success = $result.AsyncWaitHandle.WaitOne(3000)
        
        if ($success) {
            $tcpClient.EndConnect($result)
            $tcpClient.Close()
            Add-AuditResult -Category "Réseau" -Check "Port $Port" -Status "SUCCESS" -Message "$Description - Port ouvert" -Details "Port $Port accessible localement"
        } else {
            Add-AuditResult -Category "Réseau" -Check "Port $Port" -Status "ERROR" -Message "$Description - Port fermé" -Details "Port $Port non accessible"
        }
    } catch {
        Add-AuditResult -Category "Réseau" -Check "Port $Port" -Status "ERROR" -Message "$Description - Erreur de connexion" -Details $_.Exception.Message
    }
}

# =============================================================
# DÉBUT DE L'AUDIT
# =============================================================

Write-AuditLog "Début de l'audit CyberArk Vault" "INFO"
Write-AuditLog "Serveur: $env:COMPUTERNAME" "INFO"

# SECTION 1: Vérification des services essentiels
Write-AuditLog "Vérification des services CyberArk..." "INFO"

$CyberArkServices = @(
    @{Name="PrivateArk Server"; Description="Service principal Vault"},
    @{Name="CyberArk Hardened Windows Firewall"; Description="Firewall CyberArk"},
    @{Name="CyberArk Event Notification Engine"; Description="Moteur de notification"},
    @{Name="CyberArk Password Manager"; Description="Gestionnaire de mots de passe"},
    @{Name="CyberArk Scheduled Tasks Manager"; Description="Gestionnaire de tâches"}
)

foreach ($svc in $CyberArkServices) {
    try {
        $service = Get-Service -Name $svc.Name -ErrorAction Stop
        $dependentServices = $service.DependentServices | Where-Object {$_.Status -eq 'Running'}
        
        if ($service.Status -eq 'Running') {
            Add-AuditResult -Category "Services" -Check $svc.Name -Status "SUCCESS" -Message "Service en cours d'exécution" -Details "État: $($service.Status) | Démarrage: $($service.StartType)"
        } else {
            Add-AuditResult -Category "Services" -Check $svc.Name -Status "ERROR" -Message "Service arrêté" -Details "État: $($service.Status)"
        }
        
        # Vérification des services dépendants
        if ($dependentServices.Count -gt 0) {
            Add-AuditResult -Category "Services" -Check "$($svc.Name) - Dépendances" -Status "INFO" -Message "$($dependentServices.Count) service(s) dépendant(s) en cours d'exécution" -Details ($dependentServices.Name -join ", ")
        }
    } catch {
        Add-AuditResult -Category "Services" -Check $svc.Name -Status "ERROR" -Message "Service introuvable" -Details $_.Exception.Message
    }
}

# SECTION 2: Vérification détaillée du firewall
Write-AuditLog "Vérification du firewall..." "INFO"

try {
    $firewallProfiles = Get-NetFirewallProfile | Where-Object {$_.Enabled -eq 'True'}
    foreach ($profile in $firewallProfiles) {
        Add-AuditResult -Category "Firewall" -Check "Profile $($profile.Name)" -Status "WARNING" -Message "Firewall Windows activé" -Details "Le profile $($profile.Name) est activé"
    }
    
    # Vérification des règles CyberArk
    $cyberArkRules = Get-NetFirewallRule | Where-Object {$_.DisplayName -like "*CyberArk*" -or $_.DisplayName -like "*PrivateArk*"}
    if ($cyberArkRules) {
        Add-AuditResult -Category "Firewall" -Check "Règles CyberArk" -Status "SUCCESS" -Message "$($cyberArkRules.Count) règle(s) CyberArk trouvée(s)" -Details ($cyberArkRules.DisplayName -join " | ")
    }
} catch {
    Add-AuditResult -Category "Firewall" -Check "Configuration Firewall" -Status "ERROR" -Message "Erreur d'accès au firewall" -Details $_.Exception.Message
}

# SECTION 3: Test des ports avancés
Write-AuditLog "Test des ports Vault..." "INFO"

$VaultPorts = @(
    @{Port=1858; Description="Port Vault principal"},
    @{Port=1859; Description="Port Vault secondaire"},
    @{Port=443; Description="HTTPS/API"},
    @{Port=135; Description="RPC"},
    @{Port=445; Description="SMB"}
)

foreach ($portInfo in $VaultPorts) {
    Test-VaultPort -Port $portInfo.Port -Description $portInfo.Description
}

# SECTION 4: Vérification de la conformité domaine
Write-AuditLog "Vérification de l'appartenance au domaine..." "INFO"

$computerInfo = Get-CimInstance -ClassName Win32_ComputerSystem
$domainRole = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole

if ($computerInfo.PartOfDomain -eq $true) {
    Add-AuditResult -Category "Sécurité" -Check "Appartenance au domaine" -Status "ERROR" -Message "Serveur joint au domaine - Non conforme" -Details "Rôle: $domainRole | Domaine: $($computerInfo.Domain)"
} else {
    Add-AuditResult -Category "Sécurité" -Check "Appartenance au domaine" -Status "SUCCESS" -Message "Serveur non joint au domaine - Conforme" -Details "Rôle: $domainRole"
}

# SECTION 5: Analyse des performances système
Write-AuditLog "Analyse des performances..." "INFO"

# Mémoire
$memory = Get-CimInstance -ClassName Win32_OperatingSystem
$usedMemory = ($memory.TotalVisibleMemorySize - $memory.FreePhysicalMemory) / 1MB
$totalMemory = $memory.TotalVisibleMemorySize / 1MB
$memoryUsage = ($usedMemory / $totalMemory) * 100

if ($memoryUsage -gt 90) {
    Add-AuditResult -Category "Performance" -Check "Utilisation mémoire" -Status "ERROR" -Message "Mémoire élevée: $([math]::Round($memoryUsage, 2))%" -Details "Utilisé: $([math]::Round($usedMemory, 2))GB / Total: $([math]::Round($totalMemory, 2))GB"
} elseif ($memoryUsage -gt 80) {
    Add-AuditResult -Category "Performance" -Check "Utilisation mémoire" -Status "WARNING" -Message "Mémoire modérée: $([math]::Round($memoryUsage, 2))%" -Details "Utilisé: $([math]::Round($usedMemory, 2))GB / Total: $([math]::Round($totalMemory, 2))GB"
} else {
    Add-AuditResult -Category "Performance" -Check "Utilisation mémoire" -Status "SUCCESS" -Message "Mémoire normale: $([math]::Round($memoryUsage, 2))%" -Details "Utilisé: $([math]::Round($usedMemory, 2))GB / Total: $([math]::Round($totalMemory, 2))GB"
}

# Disque
$disks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3"
foreach ($disk in $disks) {
    $freeSpace = ($disk.FreeSpace / 1GB)
    $totalSpace = ($disk.Size / 1GB)
    $usagePercentage = (($totalSpace - $freeSpace) / $totalSpace) * 100
    
    if ($usagePercentage -gt 90) {
        Add-AuditResult -Category "Performance" -Check "Espace disque $($disk.DeviceID)" -Status "ERROR" -Message "Espace disque critique: $([math]::Round($usagePercentage, 2))%" -Details "Libre: $([math]::Round($freeSpace, 2))GB / Total: $([math]::Round($totalSpace, 2))GB"
    } elseif ($usagePercentage -gt 80) {
        Add-AuditResult -Category "Performance" -Check "Espace disque $($disk.DeviceID)" -Status "WARNING" -Message "Espace disque faible: $([math]::Round($usagePercentage, 2))%" -Details "Libre: $([math]::Round($freeSpace, 2))GB / Total: $([math]::Round($totalSpace, 2))GB"
    } else {
        Add-AuditResult -Category "Performance" -Check "Espace disque $($disk.DeviceID)" -Status "SUCCESS" -Message "Espace disque OK: $([math]::Round($usagePercentage, 2))%" -Details "Libre: $([math]::Round($freeSpace, 2))GB / Total: $([math]::Round($totalSpace, 2))GB"
    }
}

# SECTION 6: Vérification de la configuration réseau
Write-AuditLog "Analyse de la configuration réseau..." "INFO"

$networkAdapters = Get-NetAdapter | Where-Object {$_.Status -eq 'Up'}
foreach ($adapter in $networkAdapters) {
    $ipAddresses = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 | Where-Object {$_.IPAddress -ne '127.0.0.1'}
    foreach ($ip in $ipAddresses) {
        Add-AuditResult -Category "Réseau" -Check "Adapter $($adapter.Name)" -Status "INFO" -Message "Adresse IP: $($ip.IPAddress)" -Details "Masque: $($ip.PrefixLength) | Interface: $($adapter.InterfaceDescription)"
    }
}

# SECTION 7: Audit de sécurité
Write-AuditLog "Audit de sécurité..." "INFO"

# Vérification des politiques de sécurité
try {
    $auditPolicy = auditpol /get /category:* /r | ConvertFrom-Csv
    $failedAudits = $auditPolicy | Where-Object {$_.'Inclusion Setting' -ne "Success and Failure"}
    
    if ($failedAudits.Count -gt 10) {
        Add-AuditResult -Category "Sécurité" -Check "Politique d'audit" -Status "WARNING" -Message "Audit Windows limité" -Details "$($failedAudits.Count) catégories sans audit complet"
    }
} catch {
    Add-AuditResult -Category "Sécurité" -Check "Politique d'audit" -Status "ERROR" -Message "Impossible de récupérer la politique d'audit" -Details $_.Exception.Message
}

# Vérification des mises à jour
$lastBoot = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
$uptime = (Get-Date) - $lastBoot
Add-AuditResult -Category "Sécurité" -Check "Temps de fonctionnement" -Status "INFO" -Message "Uptime: $($uptime.Days) jours" -Details "Dernier démarrage: $lastBoot"

# SECTION 8: Vérification des processus CyberArk
Write-AuditLog "Vérification des processus CyberArk..." "INFO"

$cyberArkProcesses = Get-Process | Where-Object {$_.ProcessName -like "*cyber*" -or $_.ProcessName -like "*vault*" -or $_.ProcessName -like "*privateark*"}
if ($cyberArkProcesses) {
    Add-AuditResult -Category "Processus" -Check "Processus CyberArk" -Status "SUCCESS" -Message "$($cyberArkProcesses.Count) processus CyberArk en cours d'exécution" -Details ($cyberArkProcesses.ProcessName -join ", ")
} else {
    Add-AuditResult -Category "Processus" -Check "Processus CyberArk" -Status "WARNING" -Message "Aucun processus CyberArk détecté" -Details "Vérifier l'état des services"
}

# =============================================================
# GÉNÉRATION DU RAPPORT HTML
# =============================================================

Write-AuditLog "Génération du rapport HTML..." "INFO"

$htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Audit CyberArk Vault - $env:COMPUTERNAME</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .summary { background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .success { color: #27ae60; }
        .warning { color: #f39c12; }
        .error { color: #e74c3c; }
        .info { color: #3498db; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #34495e; color: white; }
        tr:hover { background-color: #f5f5f5; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Audit CyberArk Vault</h1>
        <p>Serveur: $env:COMPUTERNAME | Date: $(Get-Date)</p>
    </div>
    
    <div class="summary">
        <h3>📊 Résumé de l'audit</h3>
        <p><strong>Total des vérifications:</strong> $($global:AuditResults.Count)</p>
        <p class="success"><strong>Succès:</strong> $(($global:AuditResults | Where-Object {$_.Status -eq 'SUCCESS'}).Count)</p>
        <p class="warning"><strong>Avertissements:</strong> $global:WarningCount</p>
        <p class="error"><strong>Erreurs:</strong> $global:ErrorCount</p>
    </div>
    
    <h3>📋 Détail des vérifications</h3>
    <table>
        <tr>
            <th>Catégorie</th>
            <th>Vérification</th>
            <th>Statut</th>
            <th>Message</th>
            <th>Détails</th>
            <th>Horodatage</th>
        </tr>
"@

foreach ($result in $global:AuditResults) {
    $statusClass = $result.Status.ToLower()
    $htmlReport += @"
        <tr>
            <td>$($result.Category)</td>
            <td>$($result.Check)</td>
            <td class="$statusClass"><strong>$($result.Status)</strong></td>
            <td>$($result.Message)</td>
            <td><small>$($result.Details)</small></td>
            <td><small>$($result.Timestamp)</small></td>
        </tr>
"@
}

$htmlReport += @"
    </table>
    <br>
    <div class="summary">
        <p><strong>Rapport généré le:</strong> $(Get-Date)</p>
        <p><strong>Script version:</strong> 2.0</p>
    </div>
</body>
</html>
"@

$htmlReport | Out-File $ReportPath -Encoding UTF8

# SECTION 9: Envoi du rapport par email (optionnel)
if ($SendEmail) {
    Write-AuditLog "Envoi du rapport par email..." "INFO"
    try {
        $emailSubject = "Audit CyberArk Vault - $env:COMPUTERNAME - $(Get-Date -Format 'yyyy-MM-dd')"
        $emailBody = "Veuillez trouver ci-joint le rapport d'audit CyberArk Vault.<br><br>Erreurs: $global:ErrorCount | Avertissements: $global:WarningCount"
        
        Send-MailMessage -SmtpServer $SMTPServer -To $EmailTo -From "vault-audit@company.com" -Subject $emailSubject -Body $emailBody -BodyAsHtml -Attachments $ReportPath -ErrorAction Stop
        Add-AuditResult -Category "Rapport" -Check "Envoi email" -Status "SUCCESS" -Message "Rapport envoyé avec succès" -Details "Destinataire: $EmailTo"
    } catch {
        Add-AuditResult -Category "Rapport" -Check "Envoi email" -Status "ERROR" -Message "Échec de l'envoi du rapport" -Details $_.Exception.Message
    }
}

# =============================================================
# FIN DE L'AUDIT
# =============================================================

Write-AuditLog "Audit terminé" "INFO"
Write-AuditLog "Rapport généré: $ReportPath" "INFO"
Write-AuditLog "Total erreurs: $global:ErrorCount | Avertissements: $global:WarningCount" "INFO"

# Affichage du résumé final
Write-Host "`n" -NoNewline
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host "✅ AUDIT CYBERARK VAULT TERMINÉ" -ForegroundColor Green
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host "Rapport HTML: " -NoNewline -ForegroundColor White
Write-Host $ReportPath -ForegroundColor Yellow
Write-Host "Logs détaillés: " -NoNewline -ForegroundColor White
Write-Host $LogPath -ForegroundColor Yellow
Write-Host "Résumé: " -NoNewline -ForegroundColor White
Write-Host "$($global:AuditResults.Count) vérifications effectuées" -ForegroundColor Cyan
Write-Host "Statut: " -NoNewline -ForegroundColor White
Write-Host "Succès: $(($global:AuditResults | Where-Object {$_.Status -eq 'SUCCESS'}).Count) " -NoNewline -ForegroundColor Green
Write-Host "| Avertissements: $global:WarningCount " -NoNewline -ForegroundColor Yellow
Write-Host "| Erreurs: $global:ErrorCount" -ForegroundColor Red
Write-Host "=" * 60 -ForegroundColor Cyan

# Retourner le code de sortie pour les scripts automatisés
if ($global:ErrorCount -gt 0) {
    exit 1
} else {
    exit 0
}
