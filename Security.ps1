# Secure Network Simulation and IAM Management with PowerShell

# OSI Model Simulation

Function Show-OSIModel {
    # Define the OSI Model and its layers with descriptions
    $osiModel = @{
        "Physical" = "Layer 1: Deals with physical connections like cables and hardware.";
        "Data Link" = "Layer 2: Handles MAC addressing and error checking.";
        "Network" = "Layer 3: Responsible for routing and IP addressing.";
        "Transport" = "Layer 4: Manages data flow and ensures reliable communication (TCP/UDP).";
        "Session" = "Layer 5: Manages sessions between applications.";
        "Presentation" = "Layer 6: Translates data formats and manages encryption.";
        "Application" = "Layer 7: Provides services like HTTP, FTP, and email."
    }

    # Loop through each layer and print its description
    foreach ($layer in $osiModel.Keys) {
        Write-Host "$layer - $($osiModel[$layer])"
    }
}

# CIA Triad Demonstration

# Function to encrypt a file using a specified password
Function Encrypt-File {
    param (
        [Parameter(Mandatory=$true)][string]$FilePath,
        [Parameter(Mandatory=$true)][string]$Password
    )
    
    # Convert password to a secure string
    $SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
    $EncryptedFilePath = "$FilePath.enc"
    
    # Encrypt the file and save the output
    Protect-CmsMessage -Path $FilePath -To 'user@example.com' -OutFile $EncryptedFilePath
    Write-Host "File encrypted to $EncryptedFilePath"
}

# Function to decrypt an encrypted file
Function Decrypt-File {
    param (
        [Parameter(Mandatory=$true)][string]$EncryptedFilePath,
        [Parameter(Mandatory=$true)][string]$OutputPath
    )
    
    # Decrypt the file and save the output
    Unprotect-CmsMessage -Path $EncryptedFilePath -OutFile $OutputPath
    Write-Host "File decrypted to $OutputPath"
}

# Function to generate a hash of a specified file for integrity verification
Function Hash-File {
    param (
        [Parameter(Mandatory=$true)][string]$FilePath
    )
    
    # Generate SHA256 hash of the file
    $hash = Get-FileHash -Path $FilePath -Algorithm SHA256
    Write-Host "File hash: $($hash.Hash)"
}

# Function to check the availability of an IP address using ping
Function Monitor-Availability {
    param (
        [Parameter(Mandatory=$true)][string]$IPAddress
    )
    
    # Ping the specified IP address and check if it is reachable
    if (Test-Connection -ComputerName $IPAddress -Count 1 -Quiet) {
        Write-Host "$IPAddress is reachable."
    } else {
        Write-Host "$IPAddress is not reachable."
    }
}

# Security Tools Demonstration

# Function to perform a basic port scan on a specified IP address
Function Scan-Ports {
    param (
        [Parameter(Mandatory=$true)][string]$IPAddress,
        [Parameter(Mandatory=$true)][int[]]$PortRange = @(22, 80, 443, 8080) # Default port range
    )
    
    # Loop through the specified port range and check if each port is open or closed
    foreach ($port in $PortRange) {
        try {
            $connection = Test-NetConnection -ComputerName $IPAddress -Port $port
            if ($connection.TcpTestSucceeded) {
                Write-Host "Port $port on $IPAddress is OPEN."
            } else {
                Write-Host "Port $port on $IPAddress is CLOSED."
            }
        } catch {
            Write-Host "Error scanning port $port on $IPAddress."
        }
    }
}

# Function to simulate a basic vulnerability scan (mock scan)
Function Simulate-VulnerabilityScan {
    param (
        [Parameter(Mandatory=$true)][string]$IPAddress
    )
    
    # Simulate a vulnerability scan and display the result
    Write-Host "Scanning $IPAddress for vulnerabilities..."
    Start-Sleep -Seconds 2 # Simulate scan duration
    Write-Host "No critical vulnerabilities found. Minor configuration issues detected."
}

# IAM Role-Based Access Control

# Define roles and associated permissions using a hashtable
$Roles = @{
    "Admin" = @("Read", "Write", "Delete", "ManageUsers");
    "User" = @("Read", "Write");
    "Guest" = @("Read");
}

# Function to check if a role has permission to perform an action
Function Check-Permission {
    param (
        [Parameter(Mandatory=$true)][string]$Role,
        [Parameter(Mandatory=$true)][string]$Action
    )

    # Check if the specified role has the permission for the given action
    if ($Roles[$Role] -contains $Action) {
        Write-Host "Permission granted for $Role to perform $Action."
    } else {
        Write-Host "Permission denied for $Role to perform $Action."
    }
}

# Function to enforce password complexity policy
Function Enforce-PasswordPolicy {
    param (
        [Parameter(Mandatory=$true)][string]$Password
    )

    # Check if the password meets length and complexity requirements
    if ($Password.Length -ge 8 -and $Password -match '[A-Z]' -and $Password -match '[a-z]' -and $Password -match '\d') {
        Write-Host "Password meets complexity requirements."
    } else {
        Write-Host "Password does not meet complexity requirements. It must be at least 8 characters long, contain an uppercase letter, lowercase letter, and a number."
    }
}

# User Login and Activity Logging

# Define a mock user database with usernames and passwords
$UserDatabase = @{"admin"="StrongPassword123"; "user"="Password123"}

# Function to simulate user login and log activities
Function User-Login {
    param (
        [Parameter(Mandatory=$true)][string]$Username,
        [Parameter(Mandatory=$true)][string]$Password
    )

    # Check if the username and password are correct
    if ($UserDatabase.ContainsKey($Username) -and $UserDatabase[$Username] -eq $Password) {
        Write-Host "Login successful for $Username."
        # Log successful login
        Add-Content -Path "C:\user_activity.log" -Value "$(Get-Date) - User $Username logged in."
    } else {
        Write-Host "Invalid username or password."
        # Log failed login attempt
        Add-Content -Path "C:\user_activity.log" -Value "$(Get-Date) - Failed login attempt for $Username."
    }
}

# Main Menu to Execute Functions

Function Show-Menu {
    # Display menu options to the user
    Write-Host "1. Show OSI Model"
    Write-Host "2. Encrypt File"
    Write-Host "3. Decrypt File"
    Write-Host "4. Hash File"
    Write-Host "5. Monitor Availability"
    Write-Host "6. Scan Ports"
    Write-Host "7. Simulate Vulnerability Scan"
    Write-Host "8. Check Role Permission"
    Write-Host "9. Enforce Password Policy"
    Write-Host "10. User Login"
    Write-Host "11. Exit"
}

# Main program loop to handle user input and execute selected functions

Do {
    Show-Menu
    $choice = Read-Host "Enter your choice (1-11)"
    
    # Execute the corresponding function based on user choice
    Switch ($choice) {
        1 { Show-OSIModel }
        2 {
            $filePath = Read-Host "Enter file path to encrypt"
            $password = Read-Host "Enter password for encryption"
            Encrypt-File -FilePath $filePath -Password $password
        }
        3 {
            $encryptedFilePath = Read-Host "Enter encrypted file path"
            $outputPath = Read-Host "Enter output file path for decryption"
            Decrypt-File -EncryptedFilePath $encryptedFilePath -OutputPath $outputPath
        }
        4 {
            $filePath = Read-Host "Enter file path to hash"
            Hash-File -FilePath $filePath
        }
        5 {
            $ip = Read-Host "Enter IP address to monitor"
            Monitor-Availability -IPAddress $ip
        }
        6 {
            $ip = Read-Host "Enter IP address to scan"
            $ports = Read-Host "Enter port range (comma-separated, e.g., 22,80,443)"
            $portRange = $ports -split ',' | ForEach-Object { [int]$_ }
            Scan-Ports -IPAddress $ip -PortRange $portRange
        }
        7 {
            $ip = Read-Host "Enter IP address to scan for vulnerabilities"
            Simulate-VulnerabilityScan -IPAddress $ip
        }
        8 {
            $role = Read-Host "Enter role (Admin, User, Guest)"
            $action = Read-Host "Enter action to check permission for (Read, Write, Delete, ManageUsers)"
            Check-Permission -Role $role -Action $action
        }
        9 {
            $password = Read-Host "Enter password to check"
            Enforce-PasswordPolicy -Password $password
       
