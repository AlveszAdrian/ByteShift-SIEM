# SIEM Agent - Custom MSI Builder Script

# 1. Certifique-se de compilar o binário principal Wails antes
# Isso deve ser feito na pasta raiz do agent-ui:
# cd .. && wails build

# 2. Compilar o arquivo XML do Instalador (.wxs -> .wixobj)
.\wix\candle.exe installer.wxs -out installer.wixobj

# 3. Ligar o objeto num pacote final (.msi)
.\wix\light.exe -ext WixUIExtension installer.wixobj -out SIEM-Agent-v2.msi

Write-Host "✅ SIEM-Agent-v2.msi foi gerado com sucesso!" -ForegroundColor Green
