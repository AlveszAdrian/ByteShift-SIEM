<#
.SYNOPSIS
Script para testar a regra SIGMA a1b2c3d4-1111-2222-3333-aabbccddeef0
(Supply Chain - Unsigned DLL Loaded by Trusted Process).

.DESCRIPTION
Este script cria um ambiente controlado e seguro. Ele faz o seguinte:
1. Cria uma DLL em C# inofensiva e sem assinatura (mock payload).
2. Faz uma cópia local do PowerShell chamando de "python.exe" para burlar a regra Image|endswith.
3. Executa o falso "python.exe" instruindo-o a carregar a DLL na memória.
Isso gerará os eventos exatos necessários (Process Creation e Image Load) para testar a engine EDR/SIGMA.
#>

$ErrorActionPreference = "Stop"

$testDir = "C:\Temp\SiemSupplyChainTest"
if (-not (Test-Path $testDir)) {
    New-Item -ItemType Directory -Force -Path $testDir | Out-Null
}

$dllPath = "$testDir\MockUnsigned.dll"
$csPath = "$testDir\MockUnsigned.cs"
$mockPythonPath = "$testDir\python.exe"

Write-Host "[*] Preparando ambiente isolado em $testDir..." -ForegroundColor Cyan

# 1. Escrevendo o código fonte da DLL
$dllCode = @"
using System;
using System.Runtime.InteropServices;

public class SupplyChainMock
{
    public static void Run()
    {
        Console.WriteLine("[DLL] Payload não assinado carregado com sucesso pelo processo confiável.");
    }
}
"@
Set-Content -Path $csPath -Value $dllCode -Encoding UTF8

# 2. Compilando a DLL sem assinatura usando o csc.exe nativo do Windows (.NET)
$cscPath = (Get-ChildItem -Path "C:\Windows\Microsoft.NET\Framework64\v*" -Filter "csc.exe" | Sort-Object Version -Descending | Select-Object -First 1).FullName
if (-not $cscPath) {
    $cscPath = (Get-ChildItem -Path "C:\Windows\Microsoft.NET\Framework\v*" -Filter "csc.exe" | Sort-Object Version -Descending | Select-Object -First 1).FullName
}

Write-Host "[*] Compilando DLL não assinada..." -ForegroundColor Cyan
& $cscPath /target:library /out:$dllPath $csPath | Out-Null

if (-not (Test-Path $dllPath)) {
    Write-Host "[!] Falha ao compilar a DLL." -ForegroundColor Red
    exit
}
Write-Host "[+] DLL criada com sucesso: $dllPath" -ForegroundColor Green

# 3. Criando o processo "confiável" mock (python.exe)
# Copiamos o powershell.exe para python.exe. Como o ETW verifica o ImageName no Kernel,
# isso fará o evento ser logado como "\python.exe".
Write-Host "[*] Criando processo falso confiável (python.exe)..." -ForegroundColor Cyan
Copy-Item -Path "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe" -Destination $mockPythonPath -Force

# 4. Executando o mock e carregando a DLL na memória
Write-Host "[*] Executando o carregamento da DLL na memória simulando ataque Supply Chain..." -ForegroundColor Yellow

$loadCommand = @"
[Reflection.Assembly]::LoadFile('$dllPath') | Out-Null;
[SupplyChainMock]::Run();
Start-Sleep -Seconds 2;
"@

# Executa o "python.exe" (que na verdade é o PS) passando o comando de reflexão
& $mockPythonPath -NoProfile -NonInteractive -Command $loadCommand

Write-Host "[+] Teste concluído com segurança! Verifique a aba de Alertas no Dashboard." -ForegroundColor Green

# Limpeza opcional (comentado para o caso de querer analisar os arquivos)
# Remove-Item -Path $testDir -Recurse -Force
