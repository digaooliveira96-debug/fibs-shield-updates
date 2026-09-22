# ==============================================================================
# FIBS Resiliente - Motor de Execucao de Backup (backup_engine.ps1)
# Executa 24/7 de forma consistente, online e com auto-recuperacao no boot
# Compativel com Windows 7, 8, 10, 11 e Windows Server (2008 R2 a 2025)
# MODULO ESPECIAL: Blindagem de Producao para Backups Horarios (Pares/Impares)
# ==============================================================================
param (
    [string]$TaskName = "BKP_SISMOTEL",
    [switch]$RunAuditOnly,
    [switch]$ForceAudit,
    [switch]$CheckUpdateOnly,
    [switch]$ForceUpdate,
    [switch]$CheckExternalHealth,
    [switch]$Manual
)

Add-Type -AssemblyName System.Security
function Unprotect-String {
    param([string]$cipherText)
    if ([string]::IsNullOrWhiteSpace($cipherText)) { return $cipherText }
    if (-not $cipherText.StartsWith("AQAAANCMnd8BF")) { return $cipherText }
    try {
        $bytes = [Convert]::FromBase64String($cipherText)
        $decBytes = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
        return [System.Text.Encoding]::UTF8.GetString($decBytes)
    } catch { return $cipherText }
}

# Conversor JSON -> Hashtable compativel com Windows PowerShell 5.1.
# ATENCAO: NAO usar o parametro -AsHashtable do ConvertFrom-Json aqui. Ele so existe
# no PowerShell 6+; o servico roda sempre no powershell.exe 5.1 (System32), onde ele
# lanca excecao, zera o rastreador de destinos e derruba o alerta de 24 horas.
function ConvertTo-HashtableCompat {
    param($InputObject)
    if ($null -eq $InputObject) { return @{} }
    if ($InputObject -is [System.Collections.IDictionary]) { return $InputObject }
    $h = @{}
    foreach ($prop in $InputObject.psobject.Properties) {
        $v = $prop.Value
        if ($v -is [System.Management.Automation.PSCustomObject]) {
            $h[$prop.Name] = ConvertTo-HashtableCompat $v
        } else {
            $h[$prop.Name] = $v
        }
    }
    return $h
}

function Protect-String {
    param([string]$plainText)
    if ([string]::IsNullOrWhiteSpace($plainText)) { return $plainText }
    if ($plainText.StartsWith("AQAAANCMnd8BF")) { return $plainText }   # ja criptografado
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($plainText)
        $encBytes = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
        return [Convert]::ToBase64String($encBytes)
    } catch { return $plainText }
}

# Converte para forma criptografada, no proprio cliente, qualquer senha que ainda
# esteja em texto puro no config.json.
#
# Por que na primeira execucao e nao no pacote: o DPAPI cifra por maquina, entao um
# blob gerado na maquina de quem monta o instalador nao abriria no servidor do cliente.
# O pacote precisa sair com a senha legivel para a instalacao ser zero-toque; esta
# rotina garante que, assim que o sistema roda uma vez, o texto puro deixe de existir
# em disco no cliente. Idempotente: o que ja esta cifrado e ignorado.
function Convert-PlainPasswordsInConfig {
    try {
        if (-not (Test-Path $configFile)) { return }
        $cfg = Get-Content $configFile -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($null -eq $cfg) { return }
        $mudou = $false
        $campos = @()

        if ($null -ne $cfg.Preferences -and -not [string]::IsNullOrWhiteSpace($cfg.Preferences.SmtpPass) `
            -and -not $cfg.Preferences.SmtpPass.StartsWith("AQAAANCMnd8BF")) {
            $cfg.Preferences.SmtpPass = Protect-String $cfg.Preferences.SmtpPass
            $mudou = $true; $campos += "SmtpPass"
        }
        foreach ($t in $cfg.Tasks) {
            foreach ($nome in @("DbPassword", "NetworkPassword")) {
                $valor = $t.$nome
                if (-not [string]::IsNullOrWhiteSpace($valor) -and -not $valor.StartsWith("AQAAANCMnd8BF")) {
                    $t.$nome = Protect-String $valor
                    $mudou = $true; $campos += "$($t.TaskName).$nome"
                }
            }
        }

        if ($mudou) {
            $json = $cfg | ConvertTo-Json -Depth 10
            [System.IO.File]::WriteAllText($configFile, $json, [System.Text.Encoding]::UTF8)
            Log-Message "SEGURANCA: senha(s) em texto puro convertidas para forma criptografada neste servidor ($($campos -join ', ')). O config.json local nao guarda mais credencial legivel."
        }
    } catch {
        Log-Message "Aviso ao criptografar credenciais do config.json: $_"
    }
}

# 1. SHIELD DE PRIORIDADE: Forca prioridade baixa para que o Sismotel e o Firebird nunca travem
try {
    [System.Diagnostics.Process]::GetCurrentProcess().PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal
} catch {}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$configFile = Join-Path $scriptDir "config.json"

if ([string]::IsNullOrWhiteSpace($TaskName)) {
    $TaskName = "BKP_SISMOTEL"
}

# Log individual por tarefa em subpasta dedicada com rotacao automatica (Teto 5 MB)
$logDir = Join-Path $scriptDir "logs"
if (-not (Test-Path $logDir)) {
    try { New-Item -ItemType Directory -Path $logDir -Force | Out-Null } catch {}
}
$logFile = Join-Path $logDir "backup_$($TaskName)_log.txt"

# Funcao de Registro em Log com Rotacao Ativa (Limite 5 MB para evitar crescimento infinito)
function Log-Message {
    param ([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logLine = "[$timestamp] [$TaskName] $Message"
    Write-Output $logLine
    try {
        if (Test-Path $logFile) {
            $f = Get-Item $logFile -ErrorAction SilentlyContinue
            if ($f -and $f.Length -ge 5MB) {
                $oldLog = "$logFile.old"
                if (Test-Path $oldLog) { Remove-Item $oldLog -Force -ErrorAction SilentlyContinue }
                Rename-Item -Path $logFile -NewName (Split-Path $oldLog -Leaf) -Force -ErrorAction SilentlyContinue
            }
        }
        Add-Content -Path $logFile -Value $logLine -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {}
}

# Funcao de Resolucao de Unidade Mapeada para Caminho UNC Real (Suporte a Windows Service / SYSTEM)
function Resolve-MappedDrivePath {
    param ([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    $p = $Path.Trim()
    if ($p -match '^([A-Za-z]):\\?(.*)$') {
        $driveLetter = $matches[1].ToUpper()
        $subPath = $matches[2]
        
        $remotePath = $null
        try {
            $regKey = "HKCU:\Network\$driveLetter"
            if (Test-Path $regKey) {
                $remotePath = (Get-ItemProperty -Path $regKey -Name "RemotePath" -ErrorAction SilentlyContinue).RemotePath
            }
        } catch {}

        if ([string]::IsNullOrWhiteSpace($remotePath)) {
            try {
                $userSids = Get-ChildItem "Registry::HKEY_USERS" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'S-1-5-21-\d+-\d+-\d+-\d+$' }
                foreach ($sidKey in $userSids) {
                    $netKey = "$($sidKey.PSPath)\Network\$driveLetter"
                    if (Test-Path $netKey) {
                        $rp = (Get-ItemProperty -Path $netKey -Name "RemotePath" -ErrorAction SilentlyContinue).RemotePath
                        if (-not [string]::IsNullOrWhiteSpace($rp)) {
                            $remotePath = $rp
                            break
                        }
                    }
                }
            } catch {}
        }

        if ([string]::IsNullOrWhiteSpace($remotePath)) {
            try {
                $wmiDisk = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='${driveLetter}:'" -ErrorAction SilentlyContinue
                if ($null -ne $wmiDisk -and -not [string]::IsNullOrWhiteSpace($wmiDisk.ProviderName)) {
                    $remotePath = $wmiDisk.ProviderName
                }
            } catch {}
        }

        if (-not [string]::IsNullOrWhiteSpace($remotePath)) {
            $remotePath = $remotePath.TrimEnd('\')
            if (-not [string]::IsNullOrWhiteSpace($subPath)) {
                return "$remotePath\$subPath"
            }
            return $remotePath
        }
    }
    return $p
}

# ==============================================================================
# MODULO DE VERIFICACAO DE INTEGRIDADE DO BACKUP
# ==============================================================================
# Um backup que chega corrompido no destino e pior que backup nenhum, porque passa
# a falsa sensacao de protecao. Aqui o ZIP e aberto e LIDO de volta antes de o .fbk
# de origem ser descartado, e cada copia gravada e conferida byte a byte contra a
# origem antes de a politica de retencao apagar os backups antigos.
#
# NOTA TECNICA: no .NET Framework, ler o stream de uma entrada de ZIP ate o fim NAO
# valida o CRC32 (isso so acontece no .NET moderno), e a propriedade Crc32 da entrada
# nao existe nesta versao. Por isso a conferencia e feita com SHA-256 do conteudo
# descompactado contra o hash do .fbk original: detecta corrupcao silenciosa, e a
# abertura do arquivo detecta truncamento (diretorio central ausente).

function Get-Sha256OfFile {
    param([string]$Path)
    try { return (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash }
    catch { return $null }
}

function Test-BackupZipIntegrity {
    param(
        [string]$ZipPath,
        [string]$ExpectedEntryName,
        [long]$ExpectedSize,
        [string]$ExpectedSha256
    )
    $zip = $null
    try {
        try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue } catch {}

        # Truncamento / ZIP invalido estoura logo aqui (fim do diretorio central ausente)
        $zip = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)

        $entry = $zip.Entries | Where-Object { $_.Name -eq $ExpectedEntryName } | Select-Object -First 1
        if ($null -eq $entry) {
            return @{ Ok = $false; Reason = "A entrada '$ExpectedEntryName' nao existe dentro do ZIP." }
        }
        if ($entry.Length -ne $ExpectedSize) {
            return @{ Ok = $false; Reason = "Tamanho descompactado divergente: ZIP diz $($entry.Length) bytes, o .fbk tinha $ExpectedSize bytes." }
        }

        $stream = $entry.Open()
        try { $hash = (Get-FileHash -InputStream $stream -Algorithm SHA256 -ErrorAction Stop).Hash }
        finally { $stream.Close() }

        if ($hash -ne $ExpectedSha256) {
            return @{ Ok = $false; Reason = "SHA-256 do conteudo descompactado nao confere com o .fbk original (corrupcao silenciosa)." }
        }
        return @{ Ok = $true; Reason = "Conteudo conferido por SHA-256." }
    } catch {
        return @{ Ok = $false; Reason = "Nao foi possivel abrir/ler o ZIP: $_" }
    } finally {
        if ($null -ne $zip) { try { $zip.Dispose() } catch {} }
    }
}

# Funcao de Gestao da Numeracao Sequencial Limpa (ex: BKP_SISMOTEL-0000.zip)
function Get-NextBackupSequenceNumber {
    param (
        [string]$Prefix,
        [string[]]$DestinationPaths,
        [int]$ConfiguredNextNumber = 0,
        [string]$SequenceFilePath
    )
    if ([string]::IsNullOrWhiteSpace($Prefix)) { $Prefix = "BKP_SISMOTEL" }

    $seqData = @{}
    if (Test-Path $SequenceFilePath) {
        try {
            $raw = Get-Content $SequenceFilePath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($null -ne $raw) {
                foreach ($prop in $raw.psobject.Properties) {
                    $seqData[$prop.Name] = [int]$prop.Value
                }
            }
        } catch {}
    }

    # Procura maior numero nos arquivos das pastas de destino
    $maxFound = -1
    if ($null -ne $DestinationPaths) {
        foreach ($dest in $DestinationPaths) {
            if ([string]::IsNullOrWhiteSpace($dest)) { continue }
            $resolved = Resolve-MappedDrivePath $dest
            if (Test-Path $resolved) {
                try {
                    $files = Get-ChildItem -Path $resolved -Filter "$Prefix-*.zip" -File -ErrorAction SilentlyContinue
                    foreach ($f in $files) {
                        if ($f.Name -match "^$([regex]::Escape($Prefix))-(\d+)\.zip$") {
                            $num = [int]$matches[1]
                            if ($num -gt $maxFound) { $maxFound = $num }
                        }
                    }
                } catch {}
            }
        }
    }

    $currentSeq = -1
    if ($seqData.ContainsKey($Prefix)) {
        $currentSeq = [int]$seqData[$Prefix]
    }

    $candidate = $ConfiguredNextNumber
    if ($candidate -lt 0) { $candidate = 0 }

    if ($currentSeq -ge 0 -and $currentSeq -gt $candidate) {
        $candidate = $currentSeq
    }

    if ($maxFound -ge 0 -and $maxFound -ge $candidate) {
        $candidate = $maxFound + 1
    }

    # Atualiza o arquivo de sequencia para o proximo
    $seqData[$Prefix] = $candidate + 1
    try {
        $seqData | ConvertTo-Json | Set-Content -Path $SequenceFilePath -Encoding UTF8 -Force
    } catch {}

    return $candidate
}

# ==============================================================================
# MODULO DE TELEMETRIA E NOTIFICACOES POR E-MAIL (SMTP ENTERPRISE 24/7)
# ==============================================================================

# ==============================================================================
# MODULO DE TELEMETRIA E NOTIFICACOES POR E-MAIL (SMTP ENTERPRISE 24/7)
# ==============================================================================

function Format-DurationText([TimeSpan]$ts) {
    if ($ts.TotalHours -ge 1) {
        return ("{0:D2}h {1:D2}m {2:D2}s" -f [int][Math]::Floor($ts.TotalHours), $ts.Minutes, $ts.Seconds)
    } elseif ($ts.TotalMinutes -ge 1) {
        return ("{0}m {1:D2}s" -f $ts.Minutes, $ts.Seconds)
    } else {
        return ("{0}s" -f $ts.Seconds)
    }
}

function Get-BestBannerPath([string]$preferredType) {
    $assetsDir = Join-Path $scriptDir "assets"
    $candidates = @()
    
    if ($preferredType -eq "OK") {
        $candidates += Join-Path $assetsDir "mec_banner_ok.png"
        $candidates += Join-Path $scriptDir "mec_banner_ok.png"
    } elseif ($preferredType -eq "ALERT") {
        $candidates += Join-Path $assetsDir "mec_banner_alert.png"
        $candidates += Join-Path $scriptDir "mec_banner_alert.png"
    } elseif ($preferredType -eq "WARNING") {
        $candidates += Join-Path $assetsDir "mec_banner_warning.png"
        $candidates += Join-Path $scriptDir "mec_banner_warning.png"
        $candidates += Join-Path $assetsDir "mec_banner_alert.png"
        $candidates += Join-Path $scriptDir "mec_banner_alert.png"
    } elseif ($preferredType -eq "AUDIT") {
        $candidates += Join-Path $assetsDir "mec_banner_audit.png"
        $candidates += Join-Path $scriptDir "mec_banner_audit.png"
        $candidates += Join-Path $assetsDir "mec_banner_alert.png"
        $candidates += Join-Path $scriptDir "mec_banner_alert.png"
    }
    
    $candidates += Join-Path $assetsDir "banner_mec_dark.png"
    $candidates += Join-Path $scriptDir "banner_mec_dark.png"
    $candidates += Join-Path $assetsDir "logo_header_dark.png"
    $candidates += Join-Path $scriptDir "logo_header_dark.png"

    foreach ($cand in $candidates) {
        if (Test-Path $cand) { return $cand }
    }
    return $null
}

function Get-RemoteBadgesHtml([string]$anyDeskId, [string]$teamViewerId) {
    $adBadge = if (-not [string]::IsNullOrWhiteSpace($anyDeskId) -and $anyDeskId -notmatch "N.o configurado") {
        "<span style='background-color:#064e3b; color:#34d399; padding:5px 12px; border-radius:4px; font-family:Consolas,monospace; font-weight:800; font-size:15px; border:1px solid #059669; display:inline-block; letter-spacing:0.5px;'>$anyDeskId</span>"
    } else {
        "<span style='color:#94a3b8; font-style:italic; font-size:13.5px;'>N&atilde;o informado</span>"
    }
    
    $tvBadge = if (-not [string]::IsNullOrWhiteSpace($teamViewerId) -and $teamViewerId -notmatch "N.o configurado") {
        "<span style='background-color:#1e3a8a; color:#93c5fd; padding:5px 12px; border-radius:4px; font-family:Consolas,monospace; font-weight:700; font-size:14.5px; border:1px solid #2563eb; display:inline-block; letter-spacing:0.5px;'>$teamViewerId</span>"
    } else {
        "<span style='color:#94a3b8; font-style:italic; font-size:13.5px;'>N&atilde;o informado</span>"
    }
    
    return [PSCustomObject]@{ AnyDesk = $adBadge; TeamViewer = $tvBadge }
}

# Funcao de Envio de Notificacao por E-mail (SMTP)
# Envio de e-mail com retentativas. Devolve $true somente se a mensagem realmente saiu.
# Isso importa porque os cooldowns anti-flood (12h para falha, prazo do monitor para
# destino ausente) so podem ser armados APOS um envio confirmado: armar antes fazia um
# alerta perdido por queda momentanea de internet silenciar o proximo aviso por horas,
# justamente no cenario em que o cliente mais precisa ser avisado.
# Inicia um processo externo em prioridade BAIXA e so entao aguarda o termino.
# Necessario porque "Start-Process -Wait" bloqueia imediatamente, sem deixar janela
# para ajustar a prioridade: o processo roda inteiro em prioridade normal e disputa
# CPU e disco com o Firebird/Sismotel em producao.
function Start-ProcessThrottled {
    param(
        [string]$FilePath,
        [string[]]$ArgumentList,
        [string]$StdErrFile = $null,
        [string]$StdOutFile = $null,
        [int]$TimeoutSeconds = 7200
    )
    $sp = @{ FilePath = $FilePath; ArgumentList = $ArgumentList; NoNewWindow = $true; PassThru = $true }
    if (-not [string]::IsNullOrWhiteSpace($StdErrFile)) { $sp.RedirectStandardError  = $StdErrFile }
    if (-not [string]::IsNullOrWhiteSpace($StdOutFile)) { $sp.RedirectStandardOutput = $StdOutFile }

    $proc = Start-Process @sp
    try { $proc.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal } catch {}

    if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
        try { $proc.Kill() } catch {}
        Log-Message "AVISO: '$([System.IO.Path]::GetFileName($FilePath))' excedeu $TimeoutSeconds s e foi finalizado."
    }
    return $proc
}

function Send-MailWithRetry {
    param(
        [System.Net.Mail.MailMessage]$Mail,
        [string]$SmtpServer,
        [int]$Port,
        [bool]$UseSsl,
        $Pref,
        [int]$Attempts = 3
    )
    # IMPORTANTE: o resultado sai por $global:mailSent, NAO pelo valor de retorno.
    # Log-Message escreve com Write-Output; se o chamador capturasse o retorno desta
    # funcao, cada linha de log viraria parte do resultado (array = sempre verdadeiro)
    # e as mensagens de retentativa nunca chegariam ao arquivo de log.
    $global:mailSent = $false
    for ($try = 1; $try -le $Attempts; $try++) {
        $smtp = $null
        try {
            $smtp = New-Object System.Net.Mail.SmtpClient($SmtpServer, $Port)
            $smtp.EnableSsl = $UseSsl
            $smtp.DeliveryMethod = [System.Net.Mail.SmtpDeliveryMethod]::Network
            $smtp.UseDefaultCredentials = $false
            if (-not [string]::IsNullOrWhiteSpace($Pref.SmtpUser) -and -not [string]::IsNullOrWhiteSpace($Pref.SmtpPass)) {
                $smtp.Credentials = New-Object System.Net.NetworkCredential($Pref.SmtpUser, (Unprotect-String $Pref.SmtpPass))
            }
            $smtp.Timeout = 25000
            # Habilita TLS 1.2 (e 1.1) antes de conectar. Em Windows Server antigo o
            # padrao do .NET e Ssl3/Tls1.0, que os provedores de e-mail ja recusam.
            try {
                [System.Net.ServicePointManager]::SecurityProtocol = `
                    [System.Net.ServicePointManager]::SecurityProtocol `
                    -bor [System.Net.SecurityProtocolType]::Tls12 `
                    -bor [System.Net.SecurityProtocolType]::Tls11
            } catch {}
            try { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } } catch {}
            $smtp.Send($Mail)
            $global:mailSent = $true
            return
        } catch {
            if ($try -lt $Attempts) {
                $espera = 15 * $try
                Log-Message "Aviso: tentativa $try de envio de e-mail falhou ($_). Nova tentativa em ${espera}s..."
                Start-Sleep -Seconds $espera
            } else {
                Log-Message "ERRO: todas as $Attempts tentativas de envio de e-mail falharam. Ultimo erro: $_"
            }
        } finally {
            if ($null -ne $smtp) { try { $smtp.Dispose() } catch {} }
        }
    }
}

function Send-BackupNotification {
    param (
        [string]$Status,       # "SUCESSO" ou "FALHA"
        [string]$SubjectInfo,
        [string]$BodyDetails,
        [string]$ZipFile = "",
        [string]$ZipSize = "",
        [string]$FbkSize = "",
        [string]$DbPath = "",
        [string]$DbSize = "",
        [string]$DurationStr = "",
        [string]$GbakDurationStr = "",
        [string]$ZipDurationStr = "",
        [string]$CompressionRatio = "",
        [string]$FreeSpaceInfo = "",
        [string[]]$SuccessDests = @(),
        [string[]]$WarningDests = @()
    )
    try {
        if ($null -eq $global:configData -or $null -eq $global:configData.Preferences) {
            if (Test-Path $configFile) {
                try { $global:configData = Get-Content $configFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch {}
            }
        }
        if ($null -eq $global:configData -or $null -eq $global:configData.Preferences) { return }

        $pref = $global:configData.Preferences
        $smtpServer = $pref.SmtpServer
        $recipient = $pref.RecipientEmail
        $sender = $pref.SenderEmail

        if ([string]::IsNullOrWhiteSpace($smtpServer) -or [string]::IsNullOrWhiteSpace($recipient) -or [string]::IsNullOrWhiteSpace($sender)) {
            return
        }

        # Carrega metadados do cliente e politica de urgencia
        $clientName = if (-not [string]::IsNullOrWhiteSpace($pref.ClientName)) { $pref.ClientName } else { "CLIENTE SISMOTEL" }
        $anyDeskId = if (-not [string]::IsNullOrWhiteSpace($pref.AnyDeskId)) { $pref.AnyDeskId } else { "N&atilde;o configurado" }
        $teamViewerId = if (-not [string]::IsNullOrWhiteSpace($pref.TeamViewerId)) { $pref.TeamViewerId } else { "N&atilde;o configurado" }
        $cooldownHours = if ($pref.FailureCooldownHours -gt 0) { [int]$pref.FailureCooldownHours } else { 12 }
        $hostName = $env:COMPUTERNAME

        # Estado persistente para Cooldown e Auto-Recuperacao (Anti-Flood para +100 clientes)
        $stateFile = Join-Path $scriptDir "backup_state.json"
        $state = $null
        if (Test-Path $stateFile) {
            try { $state = Get-Content $stateFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch {}
        }
        if ($null -eq $state) {
            $state = [PSCustomObject]@{
                InFailureState = $false
                LastFailureAlert = $null
                InWarningState = $false
                LastWarningAlert = $null
                ConsecutiveFailures = 0
            }
        }
        if ($null -eq $state.InWarningState) { $state | Add-Member -NotePropertyName InWarningState -NotePropertyValue $false -Force }
        if ($null -eq $state.LastWarningAlert) { $state | Add-Member -NotePropertyName LastWarningAlert -NotePropertyValue $null -Force }

        $isRecovery = $false
        $shouldSend = $false
        $subjectTag = ""
        $bannerBg = "#10b981"
        $statusTitle = ""
        $bannerType = "OK"

        if ($Status -eq "SUCESSO") {
            $state.ConsecutiveFailures = 0

            if ($state.InFailureState -eq $true) {
                # RECUPERADO de falha critica - silencioso, apenas limpa o estado
                $state.InFailureState = $false
                $state.LastFailureAlert = $null
                Log-Message "Sistema recuperado de falha anterior. Backup voltou a funcionar normalmente (notificacao suprimida - Zero Spam)."
                try { $state | ConvertTo-Json | Set-Content $stateFile -Encoding UTF8 } catch {}
                return
            } elseif ($WarningDests.Count -eq 0 -and $state.InWarningState -eq $true) {
                # RECUPERADO de destino de rede offline - silencioso, apenas limpa o estado
                $state.InWarningState = $false
                $state.LastWarningAlert = $null
                Log-Message "Destino de rede reconectado. Sincronizacao voltou ao normal (notificacao suprimida - Zero Spam)."
                try { $state | ConvertTo-Json | Set-Content $stateFile -Encoding UTF8 } catch {}
                return
            } else {
                if ($WarningDests.Count -gt 0) {
                    # Destino externo/rede inacessivel: registra estado mas NAO envia e-mail imediato.
                    # O alerta so sera enviado pelo Monitor de Rede apos 24h continuas sem sincronizacao,
                    # evitando notificacoes desnecessarias por quedas rapidas de rede ou computador desligado temporariamente.
                    $state.InWarningState = $true
                    Log-Message "AVISO SILENCIOSO DE REDE: Destino(s) externo(s) inacessivel(is) nesta rotina. Monitorando acumulo (alerta sera enviado somente apos 24h continuas sem sincronizacao)."
                    Log-Message "Destinos nao sincronizados: $($WarningDests -join ' | ')"
                    try { $state | ConvertTo-Json | Set-Content $stateFile -Encoding UTF8 } catch {}
                    return
                } else {
                    # Silencio Total em Rotinas Normais com Sucesso (Zero Spam - nao envia e-mail em rotinas normais)
                    $state.InWarningState = $false
                    Log-Message "Notificacao por e-mail suprimida (Backup de rotina 100% gravado com sucesso - Zero Spam)."
                    try { $state | ConvertTo-Json | Set-Content $stateFile -Encoding UTF8 } catch {}
                    return
                }
            }
        } elseif ($Status -eq "FALHA") {
            $state.InFailureState = $true
            $state.ConsecutiveFailures++

            if ($pref.NotifyOnFailure -ne $true) {
                try { $state | ConvertTo-Json | Set-Content $stateFile -Encoding UTF8 } catch {}
                return
            }

            # Validacao de Cooldown Anti-Flood (nao mandar a cada hora se falhar repetidamente)
            if ($state.LastFailureAlert) {
                try {
                    $lastDt = [DateTime]::Parse($state.LastFailureAlert)
                    $hoursSince = ((Get-Date) - $lastDt).TotalHours
                    if ($hoursSince -lt $cooldownHours) {
                        Log-Message "ANTI-FLOOD ATIVO: Alerta de falha ja enviado ha $([Math]::Round($hoursSince, 1))h. E-mail suprimido para nao lotar a caixa de entrada (Cooldown: ${cooldownHours}h)."
                        try { $state | ConvertTo-Json | Set-Content $stateFile -Encoding UTF8 } catch {}
                        return
                    }
                } catch {}
            }

            $shouldSend = $true
            $subjectTag = "[MEC ALERTA CRITICO]"
            $statusTitle = "FALHA CRITICA NA ROTINA DE BACKUP"
            $bannerBg = "#dc2626"
            $bannerType = "ALERT"

            # NAO armar $state.LastFailureAlert aqui: o cooldown de ${cooldownHours}h so e
            # gravado depois que o envio for confirmado, la no fim desta funcao.
            try { $state | ConvertTo-Json | Set-Content $stateFile -Encoding UTF8 } catch {}
        }

        if (-not $shouldSend) { return }

        # Auto-preenchimento inteligente de telemetria se nao passado pelo chamador
        if ([string]::IsNullOrWhiteSpace($DurationStr) -and $null -ne $global:routineTimer -and $global:routineTimer.IsRunning) {
            $DurationStr = Format-DurationText $global:routineTimer.Elapsed
        }
        if ([string]::IsNullOrWhiteSpace($FreeSpaceInfo)) {
            try {
                $targetPath = if (-not [string]::IsNullOrWhiteSpace($DbPath)) { $DbPath } else { "C:\" }
                $driveLetter = [System.IO.Path]::GetPathRoot($targetPath)
                if (-not [string]::IsNullOrWhiteSpace($driveLetter)) {
                    $dInfo = New-Object System.IO.DriveInfo($driveLetter)
                    if ($dInfo.IsReady) {
                        $freeGB = [Math]::Round($dInfo.AvailableFreeSpace / 1GB, 1)
                        $totalGB = [Math]::Round($dInfo.TotalSize / 1GB, 1)
                        $FreeSpaceInfo = "$driveLetter ($freeGB GB livres de $totalGB GB)"
                    }
                }
            } catch {}
        }
        if ([string]::IsNullOrWhiteSpace($CompressionRatio) -and [double]::TryParse($DbSize, [ref]$null) -and [double]::TryParse($ZipSize, [ref]$null)) {
            $dSize = [double]$DbSize
            $zSize = [double]$ZipSize
            if ($dSize -gt 0 -and $zSize -gt 0) {
                $pct = [Math]::Round((1.0 - ($zSize / $dSize)) * 100, 1)
                if ($pct -gt 0) {
                    $CompressionRatio = "$pct% menor"
                }
            }
        }

        $remoteBadges = Get-RemoteBadgesHtml -anyDeskId $anyDeskId -teamViewerId $teamViewerId
        $port = if ($pref.SmtpPort -gt 0) { [int]$pref.SmtpPort } else { 587 }
        $useSsl = if ($null -ne $pref.SmtpUseSsl) { [bool]$pref.SmtpUseSsl } else { $false }
        $timestampNow = Get-Date -Format 'dd/MM/yyyy HH:mm:ss'

        $htmlBody = @"
<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="color-scheme" content="light dark">
  <meta name="supported-color-schemes" content="light dark">
  <title>MEC Shield Enterprise</title>
</head>
<body bgcolor="#090d16" style="margin:0; padding:0; background-color:#090d16; font-family:'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, Helvetica, Arial, sans-serif; -webkit-font-smoothing:antialiased; color:#f8fafc;">
  <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" bgcolor="#090d16" style="background-color:#090d16; padding:25px 10px;">
    <tr>
      <td align="center" bgcolor="#090d16" style="background-color:#090d16;">
        <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" bgcolor="#111827" style="max-width:660px; background-color:#111827; border-radius:12px; overflow:hidden; border:1px solid #1e293b; box-shadow:0 20px 25px -5px rgba(0, 0, 0, 0.7);">
          
          <!-- BANNER OFICIAL MEC (INLINE CID - 100% LIMPO E NITIDO) -->
          <tr>
            <td align="center" bgcolor="#0f172a" style="background-color:#0f172a; padding:0; margin:0; line-height:0;">
              <img src="cid:mec_header" alt="MEC Shield Enterprise" width="660" style="display:block; width:100%; max-width:660px; height:auto; border:0;" />
            </td>
          </tr>

          <!-- FAIXA DE STATUS PRINCIPAL -->
          <tr>
            <td bgcolor="$bannerBg" style="background-color:$bannerBg; color:#ffffff; padding:13px 28px; font-weight:800; font-size:14.5px; letter-spacing:0.5px; text-transform:uppercase;">
              &#9679; $statusTitle
            </td>
          </tr>

          <!-- CARD 1: DADOS DO CLIENTE & ACESSO RAPIDO DO SUPORTE -->
          <tr>
            <td bgcolor="#111827" style="background-color:#111827; padding:18px 28px 8px 28px;">
              <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" bgcolor="#1e293b" style="background-color:#1e293b; border:1px solid #334155; border-radius:8px; overflow:hidden;">
                <tr>
                  <td bgcolor="#0f172a" style="background-color:#0f172a; padding:11px 16px; border-bottom:1px solid #334155;">
                    <span style="color:#38bdf8; font-size:12.5px; font-weight:800; text-transform:uppercase; letter-spacing:0.5px;">[ DADOS DO CLIENTE &bull; ACESSO REMOTO ]</span>
                  </td>
                </tr>
                <tr>
                  <td bgcolor="#1e293b" style="background-color:#1e293b; padding:16px 18px;">
                    <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" bgcolor="#1e293b" style="font-size:14px; color:#ffffff;">
                      <tr>
                        <td width="36%" bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0; color:#94a3b8; font-weight:600;">Cliente / Empresa:</td>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0; font-weight:800; color:#ffffff; font-size:16px;">$clientName</td>
                      </tr>
                      <tr>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0; color:#94a3b8; font-weight:600;">Servidor / Hostname:</td>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0; font-family:Consolas,monospace; font-weight:700; color:#38bdf8; font-size:14.5px;">$hostName</td>
                      </tr>
                      <tr>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0; color:#94a3b8; font-weight:600;">AnyDesk ID:</td>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0;">$($remoteBadges.AnyDesk)</td>
                      </tr>
                      <tr>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0; color:#94a3b8; font-weight:600;">TeamViewer ID:</td>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0;">$($remoteBadges.TeamViewer)</td>
                      </tr>
                      <tr>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0; color:#94a3b8; font-weight:600;">Data e Hor&aacute;rio:</td>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0; color:#cbd5e1; font-size:13.5px;">$timestampNow</td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- CARD 2: TELEMETRIA DA ROTINA & ARMAZENAMENTO -->
          <tr>
            <td bgcolor="#111827" style="background-color:#111827; padding:8px 28px;">
              <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" bgcolor="#1e293b" style="background-color:#1e293b; border:1px solid #334155; border-radius:8px; overflow:hidden;">
                <tr>
                  <td bgcolor="#0f172a" style="background-color:#0f172a; padding:11px 16px; border-bottom:1px solid #334155;">
                    <span style="color:#34d399; font-size:12.5px; font-weight:800; text-transform:uppercase; letter-spacing:0.5px;">[ M&Eacute;TRICAS &bull; TELEMETRIA DA EXECU&Ccedil;&Atilde;O ]</span>
                  </td>
                </tr>
                <tr>
                  <td bgcolor="#1e293b" style="background-color:#1e293b; padding:16px 18px;">
                    <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" bgcolor="#1e293b" style="font-size:14px; color:#e2e8f0;">
                      <tr>
                        <td width="38%" bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0; color:#94a3b8; font-weight:600;">Tarefa Executada:</td>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0; font-weight:800; color:#ffffff; font-size:15.5px;">$TaskName</td>
                      </tr>
                      $(if ($DurationStr) {
                      "<tr>
                        <td bgcolor='#1e293b' style='background-color:#1e293b; padding:6px 0; color:#94a3b8; font-weight:600;'>Dura&ccedil;&atilde;o da Rotina:</td>
                        <td bgcolor='#1e293b' style='background-color:#1e293b; padding:6px 0; font-weight:800; color:#38bdf8; font-size:15.5px;'>$DurationStr</td>
                      </tr>"
                      })
                      $(if ($GbakDurationStr -or $ZipDurationStr) {
                      "<tr>
                        <td bgcolor='#1e293b' style='background-color:#1e293b; padding:6px 0; color:#94a3b8; font-weight:600;'>Extra&ccedil;&atilde;o &bull; Compress&atilde;o:</td>
                        <td bgcolor='#1e293b' style='background-color:#1e293b; padding:6px 0; color:#cbd5e1; font-size:14px;'>$GbakDurationStr (GBAK) &bull; $ZipDurationStr (ZIP)</td>
                      </tr>"
                      })
                      $(if ($DbPath) {
                      "<tr>
                        <td bgcolor='#1e293b' style='background-color:#1e293b; padding:6px 0; color:#94a3b8; font-weight:600;'>Banco Firebird:</td>
                        <td bgcolor='#1e293b' style='background-color:#1e293b; padding:6px 0; font-family:Consolas,monospace; font-size:13.5px; color:#cbd5e1;'>$DbPath $(if ($DbSize) { "<span style='color:#94a3b8; font-size:12.5px;'>($DbSize MB)</span>" })</td>
                      </tr>"
                      })
                      $(if ($FbkSize) {
                      "<tr>
                        <td bgcolor='#1e293b' style='background-color:#1e293b; padding:6px 0; color:#94a3b8; font-weight:600;'>Backup Bruto (FBK):</td>
                        <td bgcolor='#1e293b' style='background-color:#1e293b; padding:6px 0; font-family:Consolas,monospace; font-size:14px; color:#cbd5e1;'>$FbkSize MB</td>
                      </tr>"
                      })
                      $(if ($ZipSize) {
                      "<tr>
                        <td bgcolor='#1e293b' style='background-color:#1e293b; padding:6px 0; color:#94a3b8; font-weight:600;'>Arquivo Final (.ZIP):</td>
                        <td bgcolor='#1e293b' style='background-color:#1e293b; padding:6px 0; font-weight:800; color:#34d399; font-size:15px;'>$ZipSize MB $(if ($CompressionRatio) { "<span style='margin-left:6px; font-size:12.5px; color:#a7f3d0; font-weight:700; background-color:#064e3b; padding:3px 8px; border-radius:4px; border:1px solid #059669;'>$CompressionRatio</span>" })</td>
                      </tr>"
                      })
                      $(if ($FreeSpaceInfo) {
                      "<tr>
                        <td bgcolor='#1e293b' style='background-color:#1e293b; padding:6px 0; color:#94a3b8; font-weight:600;'>Espa&ccedil;o em Disco:</td>
                        <td bgcolor='#1e293b' style='background-color:#1e293b; padding:6px 0; font-family:Consolas,monospace; font-size:13.5px; color:#cbd5e1;'>$FreeSpaceInfo</td>
                      </tr>"
                      })
                      $(if ($SuccessDests -and $SuccessDests.Count -gt 0) {
                      $dListHtml = ""
                      foreach ($sd in $SuccessDests) {
                          $dListHtml += "<div style='margin-bottom:4px;'>&#10004; $sd</div>"
                      }
                      "<tr>
                        <td bgcolor='#1e293b' style='background-color:#1e293b; padding:6px 0; color:#94a3b8; font-weight:600;' valign='top'>Destinos Salvos:</td>
                        <td bgcolor='#1e293b' style='background-color:#1e293b; padding:6px 0; font-family:Consolas,monospace; font-size:13px; color:#34d399;'>$dListHtml</td>
                      </tr>"
                      })
                    </table>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- CARD 3: DETALHES DE ERRO & CHECKLIST DO SUPORTE (SE FALHA CRITICA) -->
          $(if ($Status -eq "FALHA" -and $BodyDetails) {
          "<tr>
            <td bgcolor='#111827' style='background-color:#111827; padding:8px 28px;'>
              <div style='background-color:#450a0a; border:1px solid #7f1d1d; border-left:4px solid #ef4444; border-radius:8px; padding:16px; font-size:13.5px; color:#fca5a5; line-height:1.6;'>
                <strong style='color:#f87171; font-size:14.5px;'>DIAGN&Oacute;STICO DA FALHA:</strong><br/>
                <div style='margin-top:8px; font-family:Consolas,monospace; white-space:pre-wrap; word-break:break-all; font-size:13px;'>$BodyDetails</div>
              </div>
            </td>
          </tr>
          <tr>
            <td bgcolor='#111827' style='background-color:#111827; padding:8px 28px;'>
              <table role='presentation' border='0' cellpadding='0' cellspacing='0' width='100%' bgcolor='#1e293b' style='background-color:#1e293b; border:1px solid #334155; border-radius:8px; overflow:hidden;'>
                <tr>
                  <td bgcolor='#0f172a' style='background-color:#0f172a; padding:11px 16px; border-bottom:1px solid #334155;'>
                    <span style='color:#f87171; font-size:12.5px; font-weight:800; text-transform:uppercase; letter-spacing:0.5px;'>[ A&Ccedil;&Atilde;O RECOMENDADA &bull; SUPORTE MEC ]</span>
                  </td>
                </tr>
                <tr>
                  <td bgcolor='#1e293b' style='background-color:#1e293b; padding:16px 18px; font-size:13.5px; color:#cbd5e1; line-height:1.7;'>
                    <div style='margin-bottom:8px;'>
                      <strong>1. Acesso Remoto:</strong> Conectar no servidor via AnyDesk ($($remoteBadges.AnyDesk)) ou TeamViewer ($($remoteBadges.TeamViewer)).
                    </div>
                    <div style='margin-bottom:8px;'>
                      <strong>2. Servi&ccedil;o Firebird:</strong> Abrir o <code>services.msc</code> e confirmar se o servi&ccedil;o <code>Firebird Server</code> est&aacute; em execu&ccedil;&atilde;o.
                    </div>
                    <div style='margin-bottom:8px;'>
                      <strong>3. Espa&ccedil;o em Disco:</strong> Verificar se a unidade de destino possui espa&ccedil;o livre suficiente para armazenar o banco.
                    </div>
                    <div>
                      <strong>4. Logs Detalhados:</strong> Consultar o log da rotina em <code>C:\Microtecs\FIBS\logs\</code>.
                    </div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>"
          })

          <!-- CARD 4: AVISO DE DESTINO EXTERNO / TERMINAL EM REDE NAO LOCALIZADO -->
          $(if ($WarningDests -and $WarningDests.Count -gt 0) {
          $wListHtml = ""
          foreach ($wd in $WarningDests) {
              $wListHtml += "<div style='margin-bottom:4px; font-weight:700;'>&#9888; $wd</div>"
          }
          "<tr>
            <td bgcolor='#111827' style='background-color:#111827; padding:8px 28px;'>
              <div style='background-color:#451a03; border:1px solid #78350f; border-left:4px solid #f59e0b; border-radius:8px; padding:16px; font-size:14px; color:#fde68a; line-height:1.65;'>
                <strong style='color:#fbbf24; font-size:15px;'>&#9888; DESTINO EXTERNO / TERMINAL RECEP&Ccedil;&Atilde;O N&Atilde;O LOCALIZADO:</strong><br/>
                <div style='margin-top:8px; color:#fef3c7;'>O backup local no servidor foi gravado com <strong>100% de sucesso e integridade</strong>. No entanto, a c&oacute;pia de conting&ecirc;ncia externa para a recep&ccedil;&atilde;o n&atilde;o respondeu no(s) seguinte(s) caminho(s):</div>
                <div style='margin:10px 0; padding:10px 14px; background-color:#1e140a; border:1px solid #b45309; border-radius:6px; font-family:Consolas,monospace; font-size:13.5px; color:#fef08a;'>$wListHtml</div>
                <div style='margin-top:8px; font-size:13.5px; color:#cbd5e1;'>
                  <strong style='color:#fbbf24;'>Causas mais frequentes identificadas no cliente:</strong>
                  <ul style='margin:6px 0 0 18px; padding:0; color:#fde68a;'>
                    <li style='margin-bottom:4px;'><strong>Terminal da Recep&ccedil;&atilde;o Desligado:</strong> O computador ou switch de rede pode estar sem energia ou em suspens&atilde;o/hiberna&ccedil;&atilde;o.</li>
                    <li style='margin-bottom:4px;'><strong>Formata&ccedil;&atilde;o ou Troca de Terminal:</strong> O computador pode ter sido formatado recentemente ou substitu&iacute;do na recep&ccedil;&atilde;o.</li>
                    <li style='margin-bottom:4px;'><strong>Credenciais de Rede Alteradas:</strong> O usu&aacute;rio ou senha do Windows na recep&ccedil;&atilde;o foram alterados ou expiraram.</li>
                    <li><strong>Mudan&ccedil;a de IP ou Cabo Solto:</strong> O endere&ccedil;o IP do terminal variou pelo roteador ou o cabo de rede foi desconectado.</li>
                  </ul>
                </div>
                <div style='margin-top:10px; font-size:12.5px; color:#94a3b8; font-style:italic;'>
                  O FIBS continuar&aacute; gerando os backups locais normalmente no servidor e tentar&aacute; sincronizar a recep&ccedil;&atilde;o na pr&oacute;xima rotina.
                </div>
              </div>
            </td>
          </tr>"
          })

          <!-- CARD 5: RESTABELECIMENTO OPERACIONAL (SE RECUPERADO) -->
          $(if ($isRecovery) {
          "<tr>
            <td bgcolor='#111827' style='background-color:#111827; padding:8px 28px;'>
              <div style='background-color:#064e3b; border:1px solid #065f46; border-left:4px solid #10b981; border-radius:8px; padding:16px; font-size:14px; color:#a7f3d0; line-height:1.65;'>
                <strong style='color:#34d399; font-size:15px;'>&#10004; RESTABELECIMENTO OPERACIONAL:</strong><br/>
                <div style='margin-top:6px;'>O backup deste cliente e a conex&atilde;o com os destinos de rede voltaram a operar com 100% de estabilidade e integridade. Os alertas anteriores foram encerrados e a prote&ccedil;&atilde;o 24/7 est&aacute; plenamente ativa.</div>
              </div>
            </td>
          </tr>"
          })

          <!-- RODAPE CORPORATIVO -->
          <tr>
            <td bgcolor="#0a0e17" style="background-color:#0a0e17; padding:18px 28px; border-top:1px solid #1f2937; text-align:center;">
              <p style="margin:0; font-size:12.5px; color:#94a3b8; font-weight:600;">
                MEC Shield Enterprise v2.2.0 &bull; FIBS Prote&ccedil;&atilde;o 24/7 &bull; Desenvolvido por Rodrigo
              </p>
              <p style="margin:5px 0 0 0; font-size:11.5px; color:#64748b;">
                Powered by MEC Tecnologias Corporativas &bull; Central de Monitoramento Cont&iacute;nuo
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
"@

        $mail = New-Object System.Net.Mail.MailMessage
        $mail.From = New-Object System.Net.Mail.MailAddress($sender, "MEC Shield - Protecao 24/7", [System.Text.Encoding]::UTF8)
        # Aceita varios destinatarios separados por ; ou , (antes, um unico valor com
        # separador lancava excecao e derrubava a notificacao inteira).
        foreach ($dest in ($recipient -split '[;,]')) {
            $d = $dest.Trim()
            if (-not [string]::IsNullOrWhiteSpace($d)) {
                try { $mail.To.Add($d) } catch { Log-Message "Aviso: destinatario invalido ignorado: '$d'" }
            }
        }
        if ($mail.To.Count -eq 0) { Log-Message "ERRO: nenhum destinatario valido em '$recipient'. E-mail nao enviado."; return }
        $mail.Subject = "$subjectTag $SubjectInfo - $clientName ($hostName)"
        $mail.SubjectEncoding = [System.Text.Encoding]::UTF8
        $mail.BodyEncoding = [System.Text.Encoding]::UTF8
        $mail.HeadersEncoding = [System.Text.Encoding]::UTF8

        $ct = New-Object System.Net.Mime.ContentType("text/html; charset=utf-8")
        $altView = [System.Net.Mail.AlternateView]::CreateAlternateViewFromString($htmlBody, [System.Text.Encoding]::UTF8, $ct.MediaType)
        $altView.ContentType = $ct

        $bannerPath = Get-BestBannerPath -preferredType $bannerType
        if ($bannerPath -and (Test-Path $bannerPath)) {
            $res = New-Object System.Net.Mail.LinkedResource($bannerPath, "image/png")
            $res.ContentId = "mec_header"
            $altView.LinkedResources.Add($res)
        }
        $mail.AlternateViews.Add($altView)

        Send-MailWithRetry -Mail $mail -SmtpServer $smtpServer -Port $port -UseSsl $useSsl -Pref $pref
        try { $mail.Dispose() } catch {}

        if ($global:mailSent) {
            Log-Message "E-mail de notificacao ($subjectTag) enviado com sucesso para: $recipient"
            if ($Status -eq "FALHA") {
                $state.LastFailureAlert = (Get-Date).ToString("o")
                try { $state | ConvertTo-Json | Set-Content $stateFile -Encoding UTF8 } catch {}
                Log-Message "Cooldown anti-flood de ${cooldownHours}h armado (a partir da entrega confirmada)."
            }
        } else {
            Log-Message "ATENCAO: o e-mail de notificacao NAO pode ser entregue. O cooldown nao sera armado, para que a proxima rotina tente avisar novamente."
        }
    } catch {
        Log-Message "Aviso: Falha ao enviar e-mail de notificacao: $_"
    }
}

function Send-WelcomeEmail {
    try {
        if ($null -eq $global:configData -or $null -eq $global:configData.Preferences) { return }
        $pref = $global:configData.Preferences
        $smtpServer = $pref.SmtpServer
        $recipient = $pref.RecipientEmail
        $sender = $pref.SenderEmail
        
        if ([string]::IsNullOrWhiteSpace($smtpServer) -or [string]::IsNullOrWhiteSpace($recipient) -or [string]::IsNullOrWhiteSpace($sender)) {
            return
        }

        $hostName = $env:COMPUTERNAME
        $port = if ($pref.SmtpPort -gt 0) { [int]$pref.SmtpPort } else { 587 }
        $useSsl = if ($null -ne $pref.SmtpUseSsl) { [bool]$pref.SmtpUseSsl } else { $false }
        $clientName = if (-not [string]::IsNullOrWhiteSpace($pref.ClientName)) { $pref.ClientName } else { "CLIENTE SISMOTEL" }
        $anyDeskId = if (-not [string]::IsNullOrWhiteSpace($pref.AnyDeskId)) { $pref.AnyDeskId } else { "N&atilde;o configurado" }
        $teamViewerId = if (-not [string]::IsNullOrWhiteSpace($pref.TeamViewerId)) { $pref.TeamViewerId } else { "N&atilde;o configurado" }
        $remoteBadges = Get-RemoteBadgesHtml -anyDeskId $anyDeskId -teamViewerId $teamViewerId
        $timestampNow = Get-Date -Format 'dd/MM/yyyy HH:mm:ss'

        $tasksHtml = ""
        if ($null -ne $global:configData.Tasks -and $global:configData.Tasks.Count -gt 0) {
            foreach ($t in $global:configData.Tasks) {
                $tName = $t.TaskName
                $tTime = if ($t.BackupTime) { $t.BackupTime } else { "Hor&aacute;rio Livre / Cont&iacute;nuo" }
                $tNetTerm = if (-not [string]::IsNullOrWhiteSpace($t.NetworkTerminalName)) { $t.NetworkTerminalName } else { "Local / N&atilde;o definido" }
                $tDestList = ""
                if ($null -ne $t.Destinations) {
                    foreach ($d in $t.Destinations) {
                        if (-not [string]::IsNullOrWhiteSpace($d)) {
                            $tDestList += "<span style='color:#38bdf8; font-family:Consolas,monospace; font-size:11.5px;'>&bull; $d</span><br/>"
                        }
                    }
                }
                if ([string]::IsNullOrWhiteSpace($tDestList)) { $tDestList = "<span style='color:#94a3b8; font-style:italic;'>Padr&atilde;o local</span>" }
                
                $tasksHtml += @"
                <tr>
                  <td bgcolor="#1e293b" style="padding:14px 16px; border-bottom:1px solid #334155; background-color:#1e293b;">
                    <div style="color:#10b981; font-weight:800; font-size:15px; margin-bottom:4px;">&#128194; $tName</div>
                    <div style="color:#cbd5e1; font-size:12.5px; line-height:1.6;">
                      <span style="color:#94a3b8; font-weight:600;">Hor&aacute;rio Agendado:</span> <strong style="color:#ffffff;">$tTime</strong> &bull; 
                      <span style="color:#94a3b8; font-weight:600;">Terminal Alerta:</span> <span style="color:#f1f5f9;">$tNetTerm</span><br/>
                      <span style="color:#94a3b8; font-weight:600;">Destinos de Armazenamento:</span><br/>
                      $tDestList
                    </div>
                  </td>
                </tr>
"@
            }
        } else {
            $tasksHtml = @"
            <tr><td bgcolor="#1e293b" style="padding:16px; color:#94a3b8; text-align:center; font-style:italic;">Nenhuma tarefa configurada no momento.</td></tr>
"@
        }

        $htmlBody = @"
<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MEC Shield Enterprise</title>
</head>
<body bgcolor="#090d16" style="margin:0; padding:0; background-color:#090d16; font-family:'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, Helvetica, Arial, sans-serif; color:#f8fafc;">
  <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" bgcolor="#090d16" style="background-color:#090d16; padding:25px 10px;">
    <tr>
      <td align="center">
        <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" bgcolor="#111827" style="background-color:#111827; max-width:660px; border-radius:12px; overflow:hidden; border:1px solid #1e293b; box-shadow:0 20px 25px -5px rgba(0, 0, 0, 0.7);">
          
          <!-- BANNER OFICIAL MEC (INLINE CID - 100% LIMPO E NITIDO) -->
          <tr>
            <td align="center" bgcolor="#0f172a" style="background-color:#0f172a; padding:0; margin:0; line-height:0;">
              <img src="cid:mec_header" alt="MEC Shield Enterprise" width="660" style="display:block; width:100%; max-width:660px; height:auto; border:0;" />
            </td>
          </tr>

          <!-- FAIXA DE STATUS PRINCIPAL -->
          <tr>
            <td bgcolor="#10b981" style="background-color:#10b981; padding:13px 28px; color:#ffffff; font-size:14.5px; font-weight:800; letter-spacing:0.5px; text-transform:uppercase;">
              &#9679; NOVA INSTALA&Ccedil;&Atilde;O FIBS &bull; MEC SHIELD ENTERPRISE ATIVADO COM SUCESSO
            </td>
          </tr>

          <!-- INTRODUCAO EXECUTIVA DE BOAS-VINDAS -->
          <tr>
            <td bgcolor="#111827" style="padding:24px 28px 12px 28px;">
              <h2 style="margin:0 0 8px 0; color:#ffffff; font-size:21px; font-weight:700;">Seja bem-vindo ao novo padr&atilde;o corporativo de seguran&ccedil;a cont&iacute;nua</h2>
              <p style="margin:0 0 14px 0; color:#cbd5e1; font-size:14px; line-height:1.65;">
                A instala&ccedil;&atilde;o do sistema corporativo <strong style="color:#10b981;">FIBS MEC Shield Enterprise (v2.2.0)</strong> foi conclu&iacute;da com &ecirc;xito neste servidor. Esta nova gera&ccedil;&atilde;o substitui integralmente as rotinas legadas e traz uma arquitetura avan&ccedil;ada de conting&ecirc;ncia concebida sob medida para o regime ininterrupto (24/7) de mot&eacute;is, blindando o banco de dados do <strong>Sismotel</strong> com prote&ccedil;&atilde;o em m&uacute;ltiplas camadas e sem nenhum impacto na agilidade da recep&ccedil;&atilde;o.
              </p>
            </td>
          </tr>

          <!-- CARD 1: DADOS DO CLIENTE & ACESSO REMOTO -->
          <tr>
            <td bgcolor="#111827" style="background-color:#111827; padding:8px 28px;">
              <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" bgcolor="#1e293b" style="background-color:#1e293b; border:1px solid #334155; border-radius:8px; overflow:hidden;">
                <tr>
                  <td bgcolor="#0f172a" style="background-color:#0f172a; padding:11px 16px; border-bottom:1px solid #334155;">
                    <span style="color:#38bdf8; font-size:12.5px; font-weight:800; text-transform:uppercase; letter-spacing:0.5px;">[ IDENTIFICA&Ccedil;&Atilde;O &bull; ACESSO REMOTO ]</span>
                  </td>
                </tr>
                <tr>
                  <td bgcolor="#1e293b" style="background-color:#1e293b; padding:16px 18px;">
                    <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" bgcolor="#1e293b" style="font-size:14px; color:#ffffff;">
                      <tr>
                        <td width="36%" bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0; color:#94a3b8; font-weight:600;">Cliente / Empresa:</td>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0; font-weight:800; color:#ffffff; font-size:16px;">$clientName</td>
                      </tr>
                      <tr>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0; color:#94a3b8; font-weight:600;">Servidor / Hostname:</td>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0; font-family:Consolas,monospace; font-weight:700; color:#38bdf8; font-size:14.5px;">$hostName</td>
                      </tr>
                      <tr>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0; color:#94a3b8; font-weight:600;">AnyDesk ID:</td>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0;">$($remoteBadges.AnyDesk)</td>
                      </tr>
                      <tr>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0; color:#94a3b8; font-weight:600;">TeamViewer ID:</td>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0;">$($remoteBadges.TeamViewer)</td>
                      </tr>
                      <tr>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0; color:#94a3b8; font-weight:600;">Data de Ativa&ccedil;&atilde;o:</td>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0; color:#cbd5e1; font-size:13.5px;">$timestampNow</td>
                      </tr>
                      <tr>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0; color:#94a3b8; font-weight:600;">Edi&ccedil;&atilde;o / Vers&atilde;o:</td>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0; color:#34d399; font-weight:700; font-size:13.5px;">v2.2.0 &bull; Enterprise Shield</td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- CARD 2: COMPARATIVO DE EVOLUCAO (O QUE MUDA DO FIBS LEGADO) -->
          <tr>
            <td bgcolor="#111827" style="background-color:#111827; padding:8px 28px;">
              <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" bgcolor="#1e293b" style="background-color:#1e293b; border:1px solid #334155; border-radius:8px; overflow:hidden;">
                <tr>
                  <td bgcolor="#0f172a" style="background-color:#0f172a; padding:12px 16px; border-bottom:1px solid #334155;">
                    <span style="color:#fbbf24; font-size:12.5px; font-weight:800; text-transform:uppercase; letter-spacing:0.5px;">[ DIFERENCIAIS TECNOL&Oacute;GICOS &bull; EVOLU&Ccedil;&Atilde;O vs. FIBS LEGADO ]</span>
                  </td>
                </tr>
                <tr>
                  <td bgcolor="#1e293b" style="background-color:#1e293b; padding:14px 16px 12px 16px;">
                    <p style="margin:0 0 12px 0; color:#cbd5e1; font-size:13px; line-height:1.6;">
                      Diferente das ferramentas e rotinas b&aacute;sicas do passado (como o <strong>FIBS antigo / Phobibs</strong>), que se limitavam a c&oacute;pias simples e com risco de congelamento na recep&ccedil;&atilde;o, o <strong style="color:#ffffff;">MEC Shield Enterprise</strong> entrega engenharia moderna de alta disponibilidade:
                    </p>
                    
                    <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="border-collapse:collapse; margin-bottom:4px;">
                      <tr bgcolor="#0f172a">
                        <td width="26%" style="padding:8px 10px; border:1px solid #334155; color:#94a3b8; font-size:11px; font-weight:800; text-transform:uppercase; letter-spacing:0.5px;">Recurso / Pilar</td>
                        <td width="37%" style="padding:8px 10px; border:1px solid #334155; color:#f87171; font-size:11px; font-weight:800; text-transform:uppercase; letter-spacing:0.5px;">FIBS Antigo (Legado)</td>
                        <td width="37%" style="padding:8px 10px; border:1px solid #334155; color:#34d399; font-size:11px; font-weight:800; text-transform:uppercase; letter-spacing:0.5px;">MEC Shield Enterprise</td>
                      </tr>
                      <tr>
                        <td style="padding:10px; border:1px solid #334155; color:#f1f5f9; font-weight:700; font-size:12px; vertical-align:top; background-color:#1e293b;">
                          Impacto no Sismotel / Recep&ccedil;&atilde;o
                        </td>
                        <td style="padding:10px; border:1px solid #334155; color:#94a3b8; font-size:11.5px; line-height:1.5; vertical-align:top; background-color:#1e293b;">
                          <span style="color:#f87171; font-weight:bold;">&#10006; Risco de Travamento:</span> C&oacute;pias com reten&ccedil;&atilde;o ou disputa de I/O, causando lentid&atilde;o e travamentos ao fechar contas ou entrar su&iacute;tes.
                        </td>
                        <td style="padding:10px; border:1px solid #334155; color:#f8fafc; font-size:11.5px; line-height:1.5; vertical-align:top; background-color:#132338;">
                          <span style="color:#34d399; font-weight:bold;">&#10004; Zero-Lock Hot-Backup:</span> Extra&ccedil;&atilde;o online oficial GBAK com prioridade CPU <em>BelowNormal</em>. 100% invis&iacute;vel, sem travar a recep&ccedil;&atilde;o.
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:10px; border:1px solid #334155; color:#f1f5f9; font-weight:700; font-size:12px; vertical-align:top; background-color:#1e293b;">
                          Auditoria de Integridade F&iacute;sica
                        </td>
                        <td style="padding:10px; border:1px solid #334155; color:#94a3b8; font-size:11.5px; line-height:1.5; vertical-align:top; background-color:#1e293b;">
                          <span style="color:#f87171; font-weight:bold;">&#10006; C&oacute;pia Cega:</span> Copiava arquivos sem validar a sa&uacute;de interna. Se o banco corrompesse, o backup nascia corrompido sem aviso.
                        </td>
                        <td style="padding:10px; border:1px solid #334155; color:#f8fafc; font-size:11.5px; line-height:1.5; vertical-align:top; background-color:#132338;">
                          <span style="color:#34d399; font-weight:bold;">&#10004; Sandbox Di&aacute;ria (03:30h):</span> Restaura e valida p&aacute;ginas f&iacute;sicas (<em>gfix -v -full</em>) e Transaction Gap em ambiente isolado toda madrugada.
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:10px; border:1px solid #334155; color:#f1f5f9; font-weight:700; font-size:12px; vertical-align:top; background-color:#1e293b;">
                          Conting&ecirc;ncia Externa 24h
                        </td>
                        <td style="padding:10px; border:1px solid #334155; color:#94a3b8; font-size:11.5px; line-height:1.5; vertical-align:top; background-color:#1e293b;">
                          <span style="color:#f87171; font-weight:bold;">&#10006; Falha Silenciosa:</span> Se a m&aacute;quina remota desligasse ou o compartilhamento ca&iacute;sse, ficava semanas sem backup externo sem avisar.
                        </td>
                        <td style="padding:10px; border:1px solid #334155; color:#f8fafc; font-size:11.5px; line-height:1.5; vertical-align:top; background-color:#132338;">
                          <span style="color:#34d399; font-weight:bold;">&#10004; Watchdog Universal 24h:</span> Monitora em tempo real caminhos UNC e unidades mapeadas. Alerta com diagn&oacute;stico se passar 24h sem nova c&oacute;pia.
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:10px; border:1px solid #334155; color:#f1f5f9; font-weight:700; font-size:12px; vertical-align:top; background-color:#1e293b;">
                          Atualiza&ccedil;&otilde;es e Manuten&ccedil;&atilde;o
                        </td>
                        <td style="padding:10px; border:1px solid #334155; color:#94a3b8; font-size:11.5px; line-height:1.5; vertical-align:top; background-color:#1e293b;">
                          <span style="color:#f87171; font-weight:bold;">&#10006; Script Est&aacute;tico:</span> Exigia visita presencial de t&eacute;cnico ou acessos remotos trabalhosos para atualizar cada servidor manualmente.
                        </td>
                        <td style="padding:10px; border:1px solid #334155; color:#f8fafc; font-size:11.5px; line-height:1.5; vertical-align:top; background-color:#132338;">
                          <span style="color:#34d399; font-weight:bold;">&#10004; MEC LiveUpdate em Nuvem:</span> Integra&ccedil;&atilde;o cont&iacute;nua via CDN GitHub corporativa; atualiza em segundo plano de forma autom&aacute;tica e segura.
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:10px; border:1px solid #334155; color:#f1f5f9; font-weight:700; font-size:12px; vertical-align:top; background-color:#1e293b;">
                          Pol&iacute;tica de Comunica&ccedil;&atilde;o
                        </td>
                        <td style="padding:10px; border:1px solid #334155; color:#94a3b8; font-size:11.5px; line-height:1.5; vertical-align:top; background-color:#1e293b;">
                          <span style="color:#f87171; font-weight:bold;">&#10006; Spam ou Omiss&atilde;o:</span> Lotava a caixa de entrada com dezenas de mensagens vazias ou n&atilde;o avisava quando o banco parava de verdade.
                        </td>
                        <td style="padding:10px; border:1px solid #334155; color:#f8fafc; font-size:11.5px; line-height:1.5; vertical-align:top; background-color:#132338;">
                          <span style="color:#34d399; font-weight:bold;">&#10004; Pol&iacute;tica Zero-Spam:</span> Rotinas de sucesso s&atilde;o 100% silenciosas; alertas imediatos apenas em falhas reais com cooldown de 12h.
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- CARD 3: TAREFAS CONFIGURADAS -->
          <tr>
            <td bgcolor="#111827" style="background-color:#111827; padding:8px 28px;">
              <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" bgcolor="#1e293b" style="background-color:#1e293b; border:1px solid #334155; border-radius:8px; overflow:hidden;">
                <tr>
                  <td bgcolor="#0f172a" style="background-color:#0f172a; padding:11px 16px; border-bottom:1px solid #334155;">
                    <span style="color:#34d399; font-size:12.5px; font-weight:800; text-transform:uppercase; letter-spacing:0.5px;">[ TAREFAS E AGENDAMENTOS CONFIGURADOS ]</span>
                  </td>
                </tr>
                $tasksHtml
              </table>
            </td>
          </tr>

          <!-- CARD 4: COMPROMISSO DE CONTINUIDADE OPERACIONAL -->
          <tr>
            <td bgcolor="#111827" style="background-color:#111827; padding:8px 28px 20px 28px;">
              <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" bgcolor="#1e293b" style="background-color:#1e293b; border:1px solid #334155; border-radius:8px; overflow:hidden;">
                <tr>
                  <td bgcolor="#0f172a" style="background-color:#0f172a; padding:11px 16px; border-bottom:1px solid #334155;">
                    <span style="color:#10b981; font-size:12.5px; font-weight:800; text-transform:uppercase; letter-spacing:0.5px;">[ SEGURAN&Ccedil;A PATRIMONIAL &bull; OPERA&Ccedil;&Atilde;O 24/7 ]</span>
                  </td>
                </tr>
                <tr>
                  <td bgcolor="#1e293b" style="background-color:#1e293b; padding:16px 18px; font-size:13.5px; color:#e2e8f0; line-height:1.7;">
                    Seus dados de faturamento, ocupa&ccedil;&atilde;o de su&iacute;tes, controle de estoque e registros fiscais do <strong>Sismotel</strong> agora est&atilde;o sob a cust&oacute;dia de um motor de conting&ecirc;ncia avan&ccedil;ado. Em caso de necessidade de suporte t&eacute;cnico, nossa equipe possui os canais de conex&atilde;o remota catalogados acima para pronto atendimento.
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- RODAPE CORPORATIVO -->
          <tr>
            <td bgcolor="#0a0e17" style="background-color:#0a0e17; padding:18px 28px; border-top:1px solid #1f2937; text-align:center;">
              <p style="margin:0; font-size:12.5px; color:#94a3b8; font-weight:600;">
                MEC Shield Enterprise v2.2.0 &bull; FIBS Prote&ccedil;&atilde;o 24/7 &bull; Desenvolvido por Rodrigo
              </p>
              <p style="margin:5px 0 0 0; font-size:11.5px; color:#64748b;">
                Powered by MEC Tecnologias Corporativas &bull; Central de Monitoramento Cont&iacute;nuo
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
"@

        $mail = New-Object System.Net.Mail.MailMessage
        $mail.From = New-Object System.Net.Mail.MailAddress($sender, "MEC Shield - Nova Instalacao", [System.Text.Encoding]::UTF8)
        # Aceita varios destinatarios separados por ; ou , (antes, um unico valor com
        # separador lancava excecao e derrubava a notificacao inteira).
        foreach ($dest in ($recipient -split '[;,]')) {
            $d = $dest.Trim()
            if (-not [string]::IsNullOrWhiteSpace($d)) {
                try { $mail.To.Add($d) } catch { Log-Message "Aviso: destinatario invalido ignorado: '$d'" }
            }
        }
        if ($mail.To.Count -eq 0) { Log-Message "ERRO: nenhum destinatario valido em '$recipient'. E-mail nao enviado."; return }
        $mail.Subject = "[NOVA INSTALACAO] FIBS MEC Shield Ativado - $clientName ($hostName)"
        $mail.SubjectEncoding = [System.Text.Encoding]::UTF8
        $mail.BodyEncoding = [System.Text.Encoding]::UTF8
        $mail.HeadersEncoding = [System.Text.Encoding]::UTF8

        $ct = New-Object System.Net.Mime.ContentType("text/html; charset=utf-8")
        $altView = [System.Net.Mail.AlternateView]::CreateAlternateViewFromString($htmlBody, [System.Text.Encoding]::UTF8, $ct.MediaType)
        $altView.ContentType = $ct

        $bannerPath = Get-BestBannerPath -preferredType "OK"
        if ($bannerPath -and (Test-Path $bannerPath)) {
            $res = New-Object System.Net.Mail.LinkedResource($bannerPath, "image/png")
            $res.ContentId = "mec_header"
            $altView.LinkedResources.Add($res)
        }
        $mail.AlternateViews.Add($altView)

        Send-MailWithRetry -Mail $mail -SmtpServer $smtpServer -Port $port -UseSsl $useSsl -Pref $pref
        try { $mail.Dispose() } catch {}

        if ($global:mailSent) {
            Log-Message "E-mail de Boas-Vindas enviado com sucesso para: $recipient"
        } else {
            Log-Message "ATENCAO: o e-mail de Boas-Vindas NAO pode ser entregue. O cooldown nao sera armado, para que a proxima rotina tente avisar novamente."
        }
    } catch {
        Log-Message "Aviso: Falha ao enviar e-mail de Boas-Vindas: $_"
    }
}

function Send-NetworkFailureAlert {
    param (
        [string]$Destination,
        [int]$DelayHours,
        [string]$TaskName,
        [string]$FailureReason = ""
    )
    try {
        if ($null -eq $global:configData -or $null -eq $global:configData.Preferences) {
            if (Test-Path $configFile) {
                try { $global:configData = Get-Content $configFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch {}
            }
        }
        if ($null -eq $global:configData -or $null -eq $global:configData.Preferences) { return }

        $pref = $global:configData.Preferences
        $smtpServer = $pref.SmtpServer
        $recipient = $pref.RecipientEmail
        $sender = $pref.SenderEmail

        if ([string]::IsNullOrWhiteSpace($smtpServer) -or [string]::IsNullOrWhiteSpace($recipient) -or [string]::IsNullOrWhiteSpace($sender)) {
            return
        }

        $hostName = $env:COMPUTERNAME
        $port = if ($pref.SmtpPort -gt 0) { [int]$pref.SmtpPort } else { 587 }
        $useSsl = if ($null -ne $pref.SmtpUseSsl) { [bool]$pref.SmtpUseSsl } else { $false }
        $clientName = if (-not [string]::IsNullOrWhiteSpace($pref.ClientName)) { $pref.ClientName } else { "CLIENTE SISMOTEL" }
        $anyDeskId = if (-not [string]::IsNullOrWhiteSpace($pref.AnyDeskId)) { $pref.AnyDeskId } else { "N&atilde;o configurado" }
        $teamViewerId = if (-not [string]::IsNullOrWhiteSpace($pref.TeamViewerId)) { $pref.TeamViewerId } else { "N&atilde;o configurado" }
        $remoteBadges = Get-RemoteBadgesHtml -anyDeskId $anyDeskId -teamViewerId $teamViewerId
        $timestampNow = Get-Date -Format 'dd/MM/yyyy HH:mm:ss'

        $daysStr = if ($DelayHours -ge 24) { "$([Math]::Floor($DelayHours / 24)) dia(s) e $($DelayHours % 24)h" } else { "${DelayHours}h" }
        $urgencyColor = if ($DelayHours -ge 48) { "#b91c1c" } elseif ($DelayHours -ge 24) { "#dc2626" } else { "#d97706" }
        $urgencyLabel = if ($DelayHours -ge 48) { "URGENTE - MAIS DE 2 DIAS" } elseif ($DelayHours -ge 24) { "ATENCAO - 24H SEM COPIA EXTERNA" } else { "PREVENTIVO - MONITORANDO" }

        $htmlBody = @"
<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MEC Shield - Alerta de Backup Externo</title>
</head>
<body bgcolor="#090d16" style="margin:0; padding:0; background-color:#090d16; font-family:'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, Helvetica, Arial, sans-serif; color:#f8fafc;">
  <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" bgcolor="#090d16" style="background-color:#090d16; padding:25px 10px;">
    <tr>
      <td align="center">
        <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" bgcolor="#111827" style="max-width:660px; background-color:#111827; border-radius:12px; overflow:hidden; border:1px solid #1e293b; box-shadow:0 20px 25px -5px rgba(0, 0, 0, 0.7);">

          <!-- BANNER OFICIAL MEC -->
          <tr>
            <td align="center" bgcolor="#0f172a" style="background-color:#0f172a; padding:0; margin:0; line-height:0;">
              <img src="cid:mec_header" alt="MEC Shield Enterprise" width="660" style="display:block; width:100%; max-width:660px; height:auto; border:0;" />
            </td>
          </tr>

          <!-- FAIXA DE STATUS PRINCIPAL -->
          <tr>
            <td bgcolor="$urgencyColor" style="background-color:$urgencyColor; color:#ffffff; padding:13px 28px; font-weight:800; font-size:14.5px; letter-spacing:0.5px; text-transform:uppercase;">
              &#9679; $urgencyLabel &bull; BACKUP EXTERNO PENDENTE
            </td>
          </tr>

          <!-- INTRODUCAO -->
          <tr>
            <td bgcolor="#111827" style="padding:22px 28px 10px 28px;">
              <h2 style="margin:0 0 6px 0; color:#fef2f2; font-size:20px; font-weight:700;">Destino Externo Sem C&oacute;pia h&aacute; $daysStr</h2>
              <p style="margin:0; color:#cbd5e1; font-size:14px; line-height:1.65;">
                O FIBS detectou que a c&oacute;pia de conting&ecirc;ncia para o destino listado abaixo est&aacute; <strong style="color:#ef4444;">interrompida h&aacute; $daysStr</strong>.
                Esta ferramenta &eacute; respons&aacute;vel por salvar o motel caso ocorra sinistro ou parada no servidor. A c&oacute;pia de emerg&ecirc;ncia externa precisa de aten&ccedil;&atilde;o t&eacute;cnica imediata.
              </p>
            </td>
          </tr>

          <!-- CARD 1: IDENTIFICACAO DO PROBLEMA -->
          <tr>
            <td bgcolor="#111827" style="padding:8px 28px;">
              <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" bgcolor="#1e293b" style="background-color:#1e293b; border-radius:8px; border:1px solid #334155; overflow:hidden;">
                <tr>
                  <td bgcolor="#0f172a" style="background-color:#0f172a; padding:11px 16px; border-bottom:1px solid #334155;">
                    <span style="color:#f59e0b; font-size:12.5px; font-weight:800; text-transform:uppercase; letter-spacing:0.5px;">[ IDENTIFICA&Ccedil;&Atilde;O DO PROBLEMA ]</span>
                  </td>
                </tr>
                <tr>
                  <td bgcolor="#1e293b" style="padding:16px 18px;">
                    <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" bgcolor="#1e293b" style="font-size:14px; color:#ffffff;">
                      <tr>
                        <td width="36%" bgcolor="#1e293b" style="padding:7px 0; color:#94a3b8; font-weight:600;">Cliente / Empresa:</td>
                        <td bgcolor="#1e293b" style="padding:7px 0; font-weight:800; color:#ffffff; font-size:16px;">$clientName</td>
                      </tr>
                      <tr>
                        <td bgcolor="#1e293b" style="padding:7px 0; color:#94a3b8; font-weight:600;">Servidor / Hostname:</td>
                        <td bgcolor="#1e293b" style="padding:7px 0; font-family:Consolas,monospace; font-weight:700; color:#38bdf8; font-size:14.5px;">$hostName</td>
                      </tr>
                      <tr>
                        <td bgcolor="#1e293b" style="padding:7px 0; color:#94a3b8; font-weight:600;">Tarefa Afetada:</td>
                        <td bgcolor="#1e293b" style="padding:7px 0; font-weight:700; color:#f1f5f9; font-size:15px;">$TaskName</td>
                      </tr>
                      <tr>
                        <td bgcolor="#1e293b" style="padding:7px 0; color:#94a3b8; font-weight:600;">Caminho do Destino:</td>
                        <td bgcolor="#1e293b" style="padding:7px 0; font-family:Consolas,monospace; font-size:12.5px; color:#fca5a5; word-break:break-all;">$Destination</td>
                      </tr>
                      <tr>
                        <td bgcolor="#1e293b" style="padding:7px 0; color:#94a3b8; font-weight:600;">Tempo sem C&oacute;pia:</td>
                        <td bgcolor="#1e293b" style="padding:7px 0; font-weight:800; color:#ef4444; font-size:16px;">$daysStr</td>
                      </tr>
                      $(if ($FailureReason) {
                      "<tr>
                        <td bgcolor='#1e293b' style='padding:7px 0; color:#94a3b8; font-weight:600;'>Causa Identificada:</td>
                        <td bgcolor='#1e293b' style='padding:7px 0; font-weight:700; color:#fbbf24; font-size:13.5px;'>$FailureReason</td>
                      </tr>"
                      })
                      <tr>
                        <td bgcolor="#1e293b" style="padding:7px 0; color:#94a3b8; font-weight:600;">Data deste Alerta:</td>
                        <td bgcolor="#1e293b" style="padding:7px 0; color:#cbd5e1; font-size:13.5px;">$timestampNow</td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- CARD 2: ESTADO DO SERVIDOR LOCAL -->
          $(if ($FailureReason -match "GBAK|Banco") {
          "<tr>
            <td bgcolor='#111827' style='padding:8px 28px;'>
              <div style='background-color:#450a0a; border:1px solid #7f1d1d; border-left:4px solid #ef4444; border-radius:8px; padding:14px 18px; font-size:14px; color:#fca5a5; line-height:1.65;'>
                <strong style='color:#f87171; font-size:15px;'>&#9888; ATEN&Ccedil;&Atilde;O: FALHA NA EXTRA&Ccedil;&Atilde;O DO BANCO DE DADOS</strong><br/>
                <div style='margin-top:6px; color:#fee2e2;'>
                  O backup externo n&atilde;o p&ocirc;de ser gerado porque a ferramenta gbak.exe encontrou erros no banco de dados Sismotel. O banco necessita de valida&ccedil;&atilde;o de integridade da equipe t&eacute;cnica MEC.
                </div>
              </div>
            </td>
          </tr>"
          } else {
          "<tr>
            <td bgcolor='#111827' style='padding:8px 28px;'>
              <div style='background-color:#052e16; border:1px solid #065f46; border-left:4px solid #10b981; border-radius:8px; padding:14px 18px; font-size:14px; color:#a7f3d0; line-height:1.65;'>
                <strong style='color:#34d399; font-size:15px;'>&#10004; SERVIDOR LOCAL: BACKUP 100% SEGURO E PROTEGIDO</strong><br/>
                <div style='margin-top:6px; color:#d1fae5;'>
                  Os backups locais continuam sendo gravados normalmente no servidor <strong>$hostName</strong> a cada ciclo de rotina.
                  O banco de dados do Sismotel est&aacute; totalmente protegido localmente. O problema est&aacute; exclusivamente na c&oacute;pia de conting&ecirc;ncia externa para o terminal.
                </div>
              </div>
            </td>
          </tr>"
          })

          <!-- CARD 3: CAUSAS MAIS PROVAVEIS -->
          <tr>
            <td bgcolor="#111827" style="padding:8px 28px;">
              <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" bgcolor="#1e293b" style="background-color:#1e293b; border-radius:8px; border:1px solid #334155; overflow:hidden;">
                <tr>
                  <td bgcolor="#0f172a" style="background-color:#0f172a; padding:11px 16px; border-bottom:1px solid #334155;">
                    <span style="color:#f87171; font-size:12.5px; font-weight:800; text-transform:uppercase; letter-spacing:0.5px;">[ CAUSAS MAIS FREQ&Uuml;ENTES ]</span>
                  </td>
                </tr>
                <tr>
                  <td bgcolor="#1e293b" style="padding:16px 18px; font-size:13.5px; color:#e2e8f0; line-height:1.75;">
                    <div style="margin-bottom:10px; display:flex; align-items:flex-start;">
                      <span style="color:#f59e0b; font-weight:800; min-width:22px; margin-right:8px;">1.</span>
                      <div><strong style="color:#fbbf24;">Terminal da Recep&ccedil;&atilde;o Desligado</strong> &mdash; O computador ou switch de rede pode estar sem energia, em hiberna&ccedil;&atilde;o ou suspens&atilde;o.</div>
                    </div>
                    <div style="margin-bottom:10px; display:flex; align-items:flex-start;">
                      <span style="color:#f59e0b; font-weight:800; min-width:22px; margin-right:8px;">2.</span>
                      <div><strong style="color:#fbbf24;">Formata&ccedil;&atilde;o ou Troca de Computador</strong> &mdash; O computador pode ter sido formatado recentemente ou substitu&iacute;do na recep&ccedil;&atilde;o, desfazendo o compartilhamento da pasta.</div>
                    </div>
                    <div style="margin-bottom:10px; display:flex; align-items:flex-start;">
                      <span style="color:#f59e0b; font-weight:800; min-width:22px; margin-right:8px;">3.</span>
                      <div><strong style="color:#fbbf24;">Credenciais Alteradas</strong> &mdash; O usu&aacute;rio ou senha do Windows na recep&ccedil;&atilde;o foram alterados ou o administrador foi desativado.</div>
                    </div>
                    <div style="margin-bottom:10px; display:flex; align-items:flex-start;">
                      <span style="color:#f59e0b; font-weight:800; min-width:22px; margin-right:8px;">4.</span>
                      <div><strong style="color:#fbbf24;">Mudan&ccedil;a de IP ou Cabo Solto</strong> &mdash; O endere&ccedil;o IP variou pelo roteador ou o cabo de rede foi desconectado na limpeza.</div>
                    </div>
                    <div style="display:flex; align-items:flex-start;">
                      <span style="color:#f59e0b; font-weight:800; min-width:22px; margin-right:8px;">5.</span>
                      <div><strong style="color:#fbbf24;">Erro F&iacute;sico no Banco Firebird</strong> &mdash; O gbak n&atilde;o conseguiu concluir a extra&ccedil;&atilde;o devido a corrup&ccedil;&atilde;o f&iacute;sica de registros ou p&aacute;ginas.</div>
                    </div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- CARD 4: CHECKLIST DO TECNICO -->
          <tr>
            <td bgcolor="#111827" style="padding:8px 28px;">
              <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" bgcolor="#1e293b" style="background-color:#1e293b; border-radius:8px; border:1px solid #334155; overflow:hidden;">
                <tr>
                  <td bgcolor="#0f172a" style="background-color:#0f172a; padding:11px 16px; border-bottom:1px solid #334155;">
                    <span style="color:#38bdf8; font-size:12.5px; font-weight:800; text-transform:uppercase; letter-spacing:0.5px;">[ CHECKLIST DE DIAGN&Oacute;STICO &bull; SUPORTE MEC ]</span>
                  </td>
                </tr>
                <tr>
                  <td bgcolor="#1e293b" style="padding:16px 18px; font-size:13.5px; color:#cbd5e1; line-height:1.75;">
                    <div style="margin-bottom:8px;">
                      <strong>1. Acessar o Servidor:</strong> Conectar via AnyDesk ($($remoteBadges.AnyDesk)) ou TeamViewer ($($remoteBadges.TeamViewer)).
                    </div>
                    <div style="margin-bottom:8px;">
                      <strong>2. Testar Conex&atilde;o de Rede:</strong> Abrir o CMD no servidor e executar <code>ping $($Destination -replace '\\.*$', '')</code>.
                    </div>
                    <div style="margin-bottom:8px;">
                      <strong>3. Validar Pasta de Destino:</strong> Pressionar <code>Win+R</code> e abrir o caminho do destino para confirmar exist&ecirc;ncia e permiss&atilde;o de grava&ccedil;&atilde;o.
                    </div>
                    <div style="margin-bottom:8px;">
                      <strong>4. Revalidar Credenciais:</strong> Abrir o <strong>MEC Shield</strong>, clicar em <em>Editar Tarefa</em> e usar o bot&atilde;o <em>Testar Conex&atilde;o</em>.
                    </div>
                    <div>
                      <strong>5. Consultar Logs:</strong> Verificar <code>C:\Microtecs\FIBS\logs\backup_${TaskName}_log.txt</code>.
                    </div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- CARD 5: ACESSO REMOTO -->
          <tr>
            <td bgcolor="#111827" style="padding:8px 28px 20px 28px;">
              <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" bgcolor="#1e293b" style="background-color:#1e293b; border-radius:8px; border:1px solid #334155; overflow:hidden;">
                <tr>
                  <td bgcolor="#0f172a" style="background-color:#0f172a; padding:11px 16px; border-bottom:1px solid #334155;">
                    <span style="color:#a78bfa; font-size:12.5px; font-weight:800; text-transform:uppercase; letter-spacing:0.5px;">[ ACESSO REMOTO AO SERVIDOR &bull; MEC SUPORTE ]</span>
                  </td>
                </tr>
                <tr>
                  <td bgcolor="#1e293b" style="padding:16px 18px;">
                    <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" bgcolor="#1e293b" style="font-size:14px; color:#ffffff;">
                      <tr>
                        <td width="36%" bgcolor="#1e293b" style="padding:6px 0; color:#94a3b8; font-weight:600;">AnyDesk ID:</td>
                        <td bgcolor="#1e293b" style="padding:6px 0;">$($remoteBadges.AnyDesk)</td>
                      </tr>
                      <tr>
                        <td bgcolor="#1e293b" style="padding:6px 0; color:#94a3b8; font-weight:600;">TeamViewer ID:</td>
                        <td bgcolor="#1e293b" style="padding:6px 0;">$($remoteBadges.TeamViewer)</td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- RODAPE CORPORATIVO -->
          <tr>
            <td bgcolor="#0a0e17" style="background-color:#0a0e17; padding:18px 28px; border-top:1px solid #1f2937; text-align:center;">
              <p style="margin:0; font-size:12.5px; color:#94a3b8; font-weight:600;">
                MEC Shield Enterprise v2.2.0 &bull; FIBS Prote&ccedil;&atilde;o 24/7 &bull; Desenvolvido por Rodrigo
              </p>
              <p style="margin:5px 0 0 0; font-size:11.5px; color:#64748b;">
                Powered by MEC Tecnologias Corporativas &bull; Central de Monitoramento Cont&iacute;nuo
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
"@

        $mail = New-Object System.Net.Mail.MailMessage
        $mail.From = New-Object System.Net.Mail.MailAddress($sender, "MEC Shield - Alerta de Backup Externo", [System.Text.Encoding]::UTF8)
        # Aceita varios destinatarios separados por ; ou , (antes, um unico valor com
        # separador lancava excecao e derrubava a notificacao inteira).
        foreach ($dest in ($recipient -split '[;,]')) {
            $d = $dest.Trim()
            if (-not [string]::IsNullOrWhiteSpace($d)) {
                try { $mail.To.Add($d) } catch { Log-Message "Aviso: destinatario invalido ignorado: '$d'" }
            }
        }
        if ($mail.To.Count -eq 0) { Log-Message "ERRO: nenhum destinatario valido em '$recipient'. E-mail nao enviado."; return }
        $mail.Subject = "[MEC ALERTA] Backup Externo Sem Sincronizar ha ${daysStr} - $clientName ($hostName)"
        $mail.SubjectEncoding = [System.Text.Encoding]::UTF8
        $mail.BodyEncoding = [System.Text.Encoding]::UTF8
        $mail.HeadersEncoding = [System.Text.Encoding]::UTF8

        $ct = New-Object System.Net.Mime.ContentType("text/html; charset=utf-8")
        $altView = [System.Net.Mail.AlternateView]::CreateAlternateViewFromString($htmlBody, [System.Text.Encoding]::UTF8, $ct.MediaType)
        $altView.ContentType = $ct

        $bannerPath = Get-BestBannerPath -preferredType "WARNING"
        if ($bannerPath -and (Test-Path $bannerPath)) {
            $res = New-Object System.Net.Mail.LinkedResource($bannerPath, "image/png")
            $res.ContentId = "mec_header"
            $altView.LinkedResources.Add($res)
        }
        $mail.AlternateViews.Add($altView)

        Send-MailWithRetry -Mail $mail -SmtpServer $smtpServer -Port $port -UseSsl $useSsl -Pref $pref
        try { $mail.Dispose() } catch {}

        if ($global:mailSent) {
            Log-Message "E-mail de ALERTA DE BACKUP EXTERNO enviado com sucesso para: $recipient"
        } else {
            Log-Message "ATENCAO: o e-mail de ALERTA DE BACKUP EXTERNO NAO pode ser entregue. O cooldown nao sera armado, para que a proxima rotina tente avisar novamente."
        }
    } catch {
        Log-Message "Aviso: Falha ao enviar e-mail de alerta de backup externo: $_"
    }
}

# ==============================================================================
# MONITOR DE SAUDE DE DESTINOS EXTERNOS E REDE (24 HORAS CONTINUO)
# ==============================================================================
function Test-ExternalDestinationsHealth {
    param (
        [string]$TaskName = "BKP_EXTERNO",
        [string[]]$Destinations = @(),
        [string]$FailureReason = ""
    )
    try {
        if ($null -eq $global:configData -or $null -eq $global:configData.Tasks) {
            if (Test-Path $configFile) {
                try { $global:configData = Get-Content $configFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch {}
            }
        }
        if ($null -eq $global:configData -or $null -eq $global:configData.Tasks) { return }

        $tConf = $global:configData.Tasks | Where-Object { $_.TaskName -eq $TaskName }
        if ($null -eq $tConf) {
            $tConf = $global:configData.Tasks | Where-Object { $_.TaskName -match "EXTERN" }
        }
        if ($null -eq $tConf) { return }

        $destsToCheck = @()
        if ($Destinations -and $Destinations.Count -gt 0) {
            $destsToCheck = $Destinations
        } elseif ($tConf.Destinations) {
            $destsToCheck = $tConf.Destinations
        }

        if ($destsToCheck.Count -eq 0) { return }

        # Prazo configuravel (Preferences.ExternalAlertHours). Padrao 24h.
        $alertHours = 24
        if ($null -ne $global:configData.Preferences -and $null -ne $global:configData.Preferences.ExternalAlertHours) {
            $cand = 0
            if ([int]::TryParse("$($global:configData.Preferences.ExternalAlertHours)", [ref]$cand) -and $cand -ge 1) {
                $alertHours = $cand
            }
        }

        $networkTrackerFile = Join-Path $scriptDir "network_tracker.json"
        $netTracker = @{}
        if (Test-Path $networkTrackerFile) {
            try { $netTracker = ConvertTo-HashtableCompat (Get-Content $networkTrackerFile -Raw -Encoding UTF8 | ConvertFrom-Json) }
    catch { Log-Message "Aviso: falha ao ler o rastreador de destinos: $_" }
        }

        $netTerm = if (-not [string]::IsNullOrWhiteSpace($tConf.NetworkTerminalName)) { $tConf.NetworkTerminalName } else { $TaskName }

        foreach ($dest in $destsToCheck) {
            $destTrim = $dest.TrimEnd('\', '/')
            if ([string]::IsNullOrWhiteSpace($destTrim)) { continue }

            if (-not $netTracker.ContainsKey($destTrim)) { $netTracker[$destTrim] = @{} }

            # Autenticacao proativa se for UNC de rede e houver credenciais
            if ($destTrim.StartsWith("\\") -and -not [string]::IsNullOrWhiteSpace($tConf.NetworkUser)) {
                $uncParts = $destTrim -split '\\'
                if ($uncParts.Count -ge 4) {
                    $uncRoot = "\\$($uncParts[2])\$($uncParts[3])"
                    try {
                        $normUser = $tConf.NetworkUser
                        while ($normUser.Contains('\\')) { $normUser = $normUser.Replace('\\', '\') }
                        $netUseArgs = @("use", "`"$uncRoot`"", "`"$($tConf.NetworkPassword)`"", "/user:`"$normUser`"", "/persistent:no")
                        Start-Process -FilePath "net.exe" -ArgumentList $netUseArgs -NoNewWindow -Wait -ErrorAction SilentlyContinue | Out-Null
                    } catch {}
                }
            }

            # Checagem Fisica Real de Arquivos .ZIP no destino
            $realLastBackupTime = $null
            $destAccessible = $false
            try {
                if (Test-Path $destTrim) {
                    $destAccessible = $true
                    $existingZips = Get-ChildItem -Path $destTrim -Filter "*.zip" -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
                    if ($existingZips -and $existingZips.Count -gt 0) {
                        $realLastBackupTime = $existingZips[0].LastWriteTime
                    }
                }
            } catch {}

            $hoursSince = 0
            $detectedReason = $FailureReason
            if ($destAccessible) {
                if ($null -ne $realLastBackupTime) {
                    $hoursSince = ((Get-Date) - $realLastBackupTime).TotalHours
                    # Atualiza o timestamp com base no arquivo real encontrado no disco
                    $netTracker[$destTrim].LastSuccess = $realLastBackupTime.ToString("o")
                    if ($hoursSince -lt $alertHours) {
                        $netTracker[$destTrim].FirstFailure = $null
                        $netTracker[$destTrim].LastAlert = $null
                    } else {
                        if (-not $netTracker[$destTrim].FirstFailure) {
                            $netTracker[$destTrim].FirstFailure = $realLastBackupTime.ToString("o")
                        }
                        if ([string]::IsNullOrWhiteSpace($detectedReason)) {
                            $detectedReason = "Arquivos de backup na pasta de destino estao desatualizados ha mais de $alertHours horas."
                        }
                    }
                } else {
                    # Pasta acessivel mas 0 arquivos .zip encontrados (pasta limpa, formatada ou recem criada)
                    if (-not $netTracker[$destTrim].FirstFailure) {
                        $netTracker[$destTrim].FirstFailure = if ($netTracker[$destTrim].LastSuccess) { $netTracker[$destTrim].LastSuccess } else { (Get-Date).ToString("o") }
                    }
                    $firstFail = [DateTime]::Parse($netTracker[$destTrim].FirstFailure)
                    $hoursSince = ((Get-Date) - $firstFail).TotalHours
                    if ([string]::IsNullOrWhiteSpace($detectedReason)) {
                        $detectedReason = "Nenhum arquivo de backup encontrado no destino (pasta vazia, formatada ou recem-criada)."
                    }
                }
            } else {
                # Destino inacessivel (desligado, descompartilhado, rede fora ou credenciais recusadas)
                if (-not $netTracker[$destTrim].FirstFailure) {
                    $netTracker[$destTrim].FirstFailure = if ($netTracker[$destTrim].LastSuccess) { $netTracker[$destTrim].LastSuccess } else { (Get-Date).ToString("o") }
                }
                $firstFail = [DateTime]::Parse($netTracker[$destTrim].FirstFailure)
                $hoursSince = ((Get-Date) - $firstFail).TotalHours
                if ([string]::IsNullOrWhiteSpace($detectedReason)) {
                    $detectedReason = "Terminal offline, pasta descompartilhada ou credenciais de rede recusadas."
                }
            }

            if ($hoursSince -ge $alertHours) {
                $lastAlert = if ($netTracker[$destTrim].LastAlert) { [DateTime]::Parse($netTracker[$destTrim].LastAlert) } else { [DateTime]::MinValue }
                if (((Get-Date) - $lastAlert).TotalHours -ge $alertHours) {
                    Log-Message "ALERTA CRITICO DISPARADO (prazo ${alertHours}h): Destino '$destTrim' sem backup valido ha $([Math]::Round($hoursSince, 1)) horas (limite ${alertHours}h). Motivo: $detectedReason"
                    $global:mailSent = $false
                    Send-NetworkFailureAlert -Destination $destTrim -DelayHours ([Math]::Round($hoursSince)) -TaskName $netTerm -FailureReason $detectedReason
                    if ($global:mailSent) {
                        $netTracker[$destTrim].LastAlert = (Get-Date).ToString("o")
                    } else {
                        # Envio falhou: nao silenciar este destino. A proxima passagem do
                        # monitor (dentro de 1 hora) tentara avisar de novo.
                        Log-Message "Alerta de '$destTrim' NAO foi entregue. Sera retentado na proxima verificacao do monitor."
                    }
                }
            }
        }

        try { $netTracker | ConvertTo-Json -Depth 10 | Set-Content $networkTrackerFile -Encoding UTF8 } catch {}
    } catch {
        Log-Message "Aviso em Test-ExternalDestinationsHealth: $_"
    }
}

# ==============================================================================
# MODULO DE AUDITORIA PREVENTIVA DE INTEGRIDADE & SAUDE DO BANCO EM SANDBOX
# ==============================================================================

function Get-OptimalSandboxDir {
    param (
        [string]$DbPath,
        [double]$DbSizeMB,
        [string[]]$ConfiguredDestinations
    )
    
    # Exige espaco livre minimo de 1.5x o tamanho do banco ou 4096 MB (o que for maior)
    $minRequiredMB = [math]::Max(4096, [math]::Round($DbSizeMB * 1.5, 0))
    $dbDrive = [System.IO.Path]::GetPathRoot($DbPath)
    
    $candidates = @()
    if ($null -ne $ConfiguredDestinations) {
        foreach ($dest in $ConfiguredDestinations) {
            if ([string]::IsNullOrWhiteSpace($dest)) { continue }
            if ($dest.StartsWith("\\")) { continue } # Nunca usar rede para sandbox temporario
            $root = [System.IO.Path]::GetPathRoot($dest)
            if (Test-Path $root) { $candidates += $dest }
        }
    }
    
    $drives = [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.IsReady -and ($_.DriveType -eq 'Fixed' -or $_.DriveType -eq 'Removable') }
    
    # Prioridade 1: Disco INTERNO (Fixed) diferente do disco do banco (ex: D: quando banco esta em C:)
    foreach ($d in ($drives | Where-Object { $_.DriveType -eq 'Fixed' -and $_.Name -ne $dbDrive })) {
        $freeMB = [math]::Round($d.AvailableFreeSpace / 1MB, 0)
        if ($freeMB -ge $minRequiredMB) {
            foreach ($c in $candidates) {
                if ([System.IO.Path]::GetPathRoot($c) -eq $d.Name) {
                    $sandboxPath = Join-Path $c "_temp_audit"
                    return [PSCustomObject]@{ Path = $sandboxPath; Drive = $d.Name; FreeMB = $freeMB; RequiredMB = $minRequiredMB; Status = "OK" }
                }
            }
            $sandboxPath = Join-Path $d.Name "BKP_SISMOTEL\_temp_audit"
            return [PSCustomObject]@{ Path = $sandboxPath; Drive = $d.Name; FreeMB = $freeMB; RequiredMB = $minRequiredMB; Status = "OK" }
        }
    }
    
    # Prioridade 2: O mesmo disco do banco (ex: C: quando so existe C:), DESDE QUE tenha espaco com folga
    $sameDrive = $drives | Where-Object { $_.Name -eq $dbDrive }
    if ($null -ne $sameDrive) {
        $freeMB = [math]::Round($sameDrive.AvailableFreeSpace / 1MB, 0)
        if ($freeMB -ge $minRequiredMB) {
            $sandboxPath = Join-Path $scriptDir "_temp_audit"
            return [PSCustomObject]@{ Path = $sandboxPath; Drive = $sameDrive.Name; FreeMB = $freeMB; RequiredMB = $minRequiredMB; Status = "OK" }
        }
    }
    
    # Prioridade 3: Disco removivel (HD externo USB E:) como ultimo recurso
    foreach ($d in ($drives | Where-Object { $_.DriveType -eq 'Removable' })) {
        $freeMB = [math]::Round($d.AvailableFreeSpace / 1MB, 0)
        if ($freeMB -ge $minRequiredMB) {
            $sandboxPath = Join-Path $d.Name "BKP_SISMOTEL\_temp_audit"
            return [PSCustomObject]@{ Path = $sandboxPath; Drive = $d.Name; FreeMB = $freeMB; RequiredMB = $minRequiredMB; Status = "OK" }
        }
    }
    
    # Nenhum disco possui espaco suficiente
    return [PSCustomObject]@{ Path = $null; Drive = $null; FreeMB = 0; RequiredMB = $minRequiredMB; Status = "INSUFFICIENT_SPACE" }
}

function Update-ConfigAuditDate {
    param ([string]$NewDate)
    try {
        if (Test-Path $configFile) {
            $cfg = Get-Content $configFile -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($null -ne $cfg.Preferences) {
                $cfg.Preferences.LastAuditDate = $NewDate
                $cfgJson = $cfg | ConvertTo-Json -Depth 10
                [System.IO.File]::WriteAllText($configFile, $cfgJson, [System.Text.Encoding]::UTF8)
            }
        }
    } catch {}
}

function Send-AuditAlertNotification {
    param (
        [string]$ClientName,
        [string]$AnyDeskId,
        [string]$TeamViewerId,
        [string]$DbPath,
        [int]$RecordErrors,
        [int]$PageErrors,
        [long]$TransactionGap,
        [long]$NextTransaction,
        [string]$AuditLogSnippet
    )
    try {
        if ($null -eq $global:configData -or $null -eq $global:configData.Preferences) {
            if (Test-Path $configFile) {
                try { $global:configData = Get-Content $configFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch {}
            }
        }
        if ($null -eq $global:configData -or $null -eq $global:configData.Preferences) { return }

        $pref = $global:configData.Preferences
        $smtpServer = $pref.SmtpServer
        $recipient = $pref.RecipientEmail
        $sender = $pref.SenderEmail

        if ([string]::IsNullOrWhiteSpace($smtpServer) -or [string]::IsNullOrWhiteSpace($recipient) -or [string]::IsNullOrWhiteSpace($sender)) {
            return
        }

        $hostName = $env:COMPUTERNAME
        $port = if ($pref.SmtpPort -gt 0) { [int]$pref.SmtpPort } else { 587 }
        $useSsl = if ($null -ne $pref.SmtpUseSsl) { [bool]$pref.SmtpUseSsl } else { $false }
        $cleanClient = if (-not [string]::IsNullOrWhiteSpace($ClientName)) { $ClientName } elseif (-not [string]::IsNullOrWhiteSpace($pref.ClientName)) { $pref.ClientName } else { "CLIENTE SISMOTEL" }
        $cleanAnyDesk = if (-not [string]::IsNullOrWhiteSpace($AnyDeskId)) { $AnyDeskId } elseif (-not [string]::IsNullOrWhiteSpace($pref.AnyDeskId)) { $pref.AnyDeskId } else { "N&atilde;o configurado" }
        $cleanTv = if (-not [string]::IsNullOrWhiteSpace($TeamViewerId)) { $TeamViewerId } elseif (-not [string]::IsNullOrWhiteSpace($pref.TeamViewerId)) { $pref.TeamViewerId } else { "N&atilde;o configurado" }
        $remoteBadges = Get-RemoteBadgesHtml -anyDeskId $cleanAnyDesk -teamViewerId $cleanTv
        $timestampNow = Get-Date -Format 'dd/MM/yyyy HH:mm:ss'

        $recordColor = if ($RecordErrors -gt 0) { "#ef4444" } else { "#10b981" }
        $pageColor = if ($PageErrors -gt 0) { "#ef4444" } else { "#10b981" }
        $gapColor = if ($TransactionGap -ge 200000) { "#f59e0b" } else { "#10b981" }
        $limitColor = if ($NextTransaction -ge 1500000000) { "#ef4444" } else { "#10b981" }

        $htmlBody = @"
<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MEC Shield - Auditoria de Integridade</title>
</head>
<body bgcolor="#090d16" style="margin:0; padding:0; background-color:#090d16; font-family:'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, Helvetica, Arial, sans-serif; color:#f8fafc;">
  <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" bgcolor="#090d16" style="background-color:#090d16; padding:25px 10px;">
    <tr>
      <td align="center">
        <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" bgcolor="#111827" style="max-width:660px; background-color:#111827; border-radius:12px; overflow:hidden; border:1px solid #1e293b; box-shadow:0 20px 25px -5px rgba(0, 0, 0, 0.7);">
          
          <!-- BANNER OFICIAL MEC (INLINE CID - 100% LIMPO E NITIDO) -->
          <tr>
            <td align="center" bgcolor="#0f172a" style="background-color:#0f172a; padding:0; margin:0; line-height:0;">
              <img src="cid:mec_header" alt="MEC Shield Enterprise" width="660" style="display:block; width:100%; max-width:660px; height:auto; border:0;" />
            </td>
          </tr>

          <!-- FAIXA DE STATUS PRINCIPAL -->
          <tr>
            <td bgcolor="#b91c1c" style="background-color:#b91c1c; color:#ffffff; padding:13px 28px; font-weight:800; font-size:14.5px; letter-spacing:0.5px; text-transform:uppercase;">
              &#9679; AUDITORIA PREVENTIVA &bull; ANOMALIA DETECTADA NO FIREBIRD
            </td>
          </tr>

          <!-- TITULO -->
          <tr>
            <td bgcolor="#111827" style="background-color:#111827; padding:22px 28px 10px 28px;">
              <h2 style="margin:0 0 6px 0; color:#fef2f2; font-size:20px; font-weight:700;">Inconsist&ecirc;ncia Identificada na Auditoria em Sandbox</h2>
              <p style="margin:0; color:#cbd5e1; font-size:14px; line-height:1.65;">
                A auditoria preventiva di&aacute;ria executada em sandbox isolado identificou anomalias no banco de dados Firebird. <span style="color:#34d399; font-weight:600;">O banco ativo no motel permanece operando normalmente sem paradas</span>, por&eacute;m requer interven&ccedil;&atilde;o t&eacute;cnica preventiva programada da equipe MEC para preservar a integridade dos dados.
              </p>
            </td>
          </tr>

          <!-- CARD 1: DADOS DO CLIENTE & ACESSO REMOTO -->
          <tr>
            <td bgcolor="#111827" style="background-color:#111827; padding:8px 28px;">
              <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" bgcolor="#1e293b" style="background-color:#1e293b; border:1px solid #334155; border-radius:8px; overflow:hidden;">
                <tr>
                  <td bgcolor="#0f172a" style="background-color:#0f172a; padding:11px 16px; border-bottom:1px solid #334155;">
                    <span style="color:#38bdf8; font-size:12.5px; font-weight:800; text-transform:uppercase; letter-spacing:0.5px;">[ DADOS DO CLIENTE &bull; ACESSO REMOTO ]</span>
                  </td>
                </tr>
                <tr>
                  <td bgcolor="#1e293b" style="background-color:#1e293b; padding:16px 18px;">
                    <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" bgcolor="#1e293b" style="font-size:14px; color:#ffffff;">
                      <tr>
                        <td width="36%" bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0; color:#94a3b8; font-weight:600;">Cliente / Empresa:</td>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0; font-weight:800; color:#ffffff; font-size:16px;">$cleanClient</td>
                      </tr>
                      <tr>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0; color:#94a3b8; font-weight:600;">Terminal / Servidor:</td>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0; font-family:Consolas,monospace; font-weight:700; color:#38bdf8; font-size:14.5px;">$hostName</td>
                      </tr>
                      <tr>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0; color:#94a3b8; font-weight:600;">AnyDesk ID:</td>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0;">$($remoteBadges.AnyDesk)</td>
                      </tr>
                      <tr>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0; color:#94a3b8; font-weight:600;">TeamViewer ID:</td>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0;">$($remoteBadges.TeamViewer)</td>
                      </tr>
                      <tr>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0; color:#94a3b8; font-weight:600;">Banco Auditado:</td>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0; font-family:Consolas,monospace; font-size:13px; color:#cbd5e1; word-break:break-all;">$DbPath</td>
                      </tr>
                      <tr>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0; color:#94a3b8; font-weight:600;">Data da Auditoria:</td>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0; color:#cbd5e1; font-size:13.5px;">$timestampNow</td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- CARD 2: RESULTADO DO DIAGNOSTICO FISICO -->
          <tr>
            <td bgcolor="#111827" style="background-color:#111827; padding:8px 28px;">
              <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" bgcolor="#1e293b" style="background-color:#1e293b; border:1px solid #334155; border-radius:8px; overflow:hidden;">
                <tr>
                  <td bgcolor="#0f172a" style="background-color:#0f172a; padding:11px 16px; border-bottom:1px solid #334155;">
                    <span style="color:#f87171; font-size:12.5px; font-weight:800; text-transform:uppercase; letter-spacing:0.5px;">[ M&Eacute;TRICAS DE INTEGRIDADE &bull; SANDBOX FIREBIRD ]</span>
                  </td>
                </tr>
                <tr>
                  <td bgcolor="#1e293b" style="background-color:#1e293b; padding:16px 18px;">
                    <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" bgcolor="#1e293b" style="font-size:14px; color:#e2e8f0;">
                      <tr>
                        <td width="55%" bgcolor="#1e293b" style="background-color:#1e293b; padding:7px 0; color:#cbd5e1;">Erros de N&iacute;vel de Registro (Record Errors):</td>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:7px 0; font-family:Consolas,monospace; font-weight:800; font-size:15px; color:$recordColor;">$RecordErrors</td>
                      </tr>
                      <tr>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:7px 0; color:#cbd5e1;">Erros de P&aacute;ginas de Banco (Page Errors):</td>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:7px 0; font-family:Consolas,monospace; font-weight:800; font-size:15px; color:$pageColor;">$PageErrors</td>
                      </tr>
                      <tr>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:7px 0; color:#cbd5e1;">Transaction Gap (Next - Oldest):</td>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:7px 0; font-family:Consolas,monospace; font-weight:800; font-size:15px; color:$gapColor;">$TransactionGap</td>
                      </tr>
                      <tr>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:7px 0; color:#cbd5e1;">Contador de Transa&ccedil;&otilde;es (Pr&oacute;xima):</td>
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:7px 0; font-family:Consolas,monospace; font-weight:700; font-size:14.5px; color:$limitColor;">$NextTransaction</td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- CARD 3: PLANO DE ACAO RECOMENDADO -->
          <tr>
            <td bgcolor="#111827" style="background-color:#111827; padding:8px 28px;">
              <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" bgcolor="#1e293b" style="background-color:#1e293b; border:1px solid #334155; border-radius:8px; overflow:hidden;">
                <tr>
                  <td bgcolor="#0f172a" style="background-color:#0f172a; padding:11px 16px; border-bottom:1px solid #334155;">
                    <span style="color:#fbbf24; font-size:12.5px; font-weight:800; text-transform:uppercase; letter-spacing:0.5px;">[ PROCEDIMENTO RECOMENDADO &bull; SUPORTE MEC ]</span>
                  </td>
                </tr>
                <tr>
                  <td bgcolor="#1e293b" style="background-color:#1e293b; padding:16px 18px; font-size:13.5px; color:#cbd5e1; line-height:1.7;">
                    <div style="margin-bottom:8px;">
                      <strong>1. Acesso Remoto:</strong> Conectar via AnyDesk ($($remoteBadges.AnyDesk)) ou TeamViewer ($($remoteBadges.TeamViewer)).
                    </div>
                    <div style="margin-bottom:8px;">
                      <strong>2. Se Record Errors &gt; 0:</strong> Agendar manuten&ccedil;&atilde;o preventiva em hor&aacute;rio de menor fluxo e executar o utilit&aacute;rio <code>ReparadorFB.exe</code> para saneamento.
                    </div>
                    <div>
                      <strong>3. Se Transaction Gap Elevado:</strong> Investigar esta&ccedil;&otilde;es com telas presas no Sismotel ou executar varredura de Sweep / <code>fixtranslimit.exe</code>.
                    </div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- DETALHES DO LOG (SNIPPET MONOSPACE) -->
          $(if (-not [string]::IsNullOrWhiteSpace($AuditLogSnippet)) {
          "<tr>
            <td bgcolor='#111827' style='background-color:#111827; padding:8px 28px 20px 28px;'>
              <div style='background-color:#020617; border:1px solid #1e293b; border-radius:6px; padding:14px; font-family:Consolas,monospace; font-size:12px; color:#94a3b8; max-height:180px; overflow:hidden; white-space:pre-wrap;'>$AuditLogSnippet</div>
            </td>
          </tr>"
          })

          <!-- RODAPE CORPORATIVO -->
          <tr>
            <td bgcolor="#0a0e17" style="background-color:#0a0e17; padding:18px 28px; border-top:1px solid #1f2937; text-align:center;">
              <p style="margin:0; font-size:12.5px; color:#94a3b8; font-weight:600;">
                MEC Shield Enterprise v2.2.0 &bull; FIBS Prote&ccedil;&atilde;o 24/7 &bull; Desenvolvido por Rodrigo
              </p>
              <p style="margin:5px 0 0 0; font-size:11.5px; color:#64748b;">
                Powered by MEC Tecnologias Corporativas &bull; Auditoria Preventiva Di&aacute;ria
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
"@

        $mail = New-Object System.Net.Mail.MailMessage
        $mail.From = New-Object System.Net.Mail.MailAddress($sender, "MEC Shield - Auditoria Sismotel", [System.Text.Encoding]::UTF8)
        # Aceita varios destinatarios separados por ; ou , (antes, um unico valor com
        # separador lancava excecao e derrubava a notificacao inteira).
        foreach ($dest in ($recipient -split '[;,]')) {
            $d = $dest.Trim()
            if (-not [string]::IsNullOrWhiteSpace($d)) {
                try { $mail.To.Add($d) } catch { Log-Message "Aviso: destinatario invalido ignorado: '$d'" }
            }
        }
        if ($mail.To.Count -eq 0) { Log-Message "ERRO: nenhum destinatario valido em '$recipient'. E-mail nao enviado."; return }
        $mail.Subject = "[ALERTA DE BANCO SISMOTEL] Anomalia Detectada em Auditoria - $cleanClient ($hostName)"
        $mail.SubjectEncoding = [System.Text.Encoding]::UTF8
        $mail.BodyEncoding = [System.Text.Encoding]::UTF8
        $mail.HeadersEncoding = [System.Text.Encoding]::UTF8

        $ct = New-Object System.Net.Mime.ContentType("text/html; charset=utf-8")
        $altView = [System.Net.Mail.AlternateView]::CreateAlternateViewFromString($htmlBody, [System.Text.Encoding]::UTF8, $ct.MediaType)
        $altView.ContentType = $ct

        $bannerPath = Get-BestBannerPath -preferredType "AUDIT"
        if ($bannerPath -and (Test-Path $bannerPath)) {
            $res = New-Object System.Net.Mail.LinkedResource($bannerPath, "image/png")
            $res.ContentId = "mec_header"
            $altView.LinkedResources.Add($res)
        }
        $mail.AlternateViews.Add($altView)

        Send-MailWithRetry -Mail $mail -SmtpServer $smtpServer -Port $port -UseSsl $useSsl -Pref $pref
        try { $mail.Dispose() } catch {}

        if ($global:mailSent) {
            Log-Message "E-mail de ALERTA CRITICO DE BANCO enviado com sucesso para: $recipient"
        } else {
            Log-Message "ATENCAO: o e-mail de ALERTA CRITICO DE BANCO NAO pode ser entregue. O cooldown nao sera armado, para que a proxima rotina tente avisar novamente."
        }
    } catch {
        Log-Message "Aviso: Falha ao enviar e-mail de alerta de banco: $_"
    }
}

function Invoke-DatabaseHealthAudit {
    param (
        [string]$TaskName,
        [switch]$Force
    )
    
    Log-Message "--------------------------------------------------------------------------------"
    Log-Message "[AUDITORIA DE SAUDE] Iniciando diagnostico preventivo de integridade do Sismotel..."
    
    if ($null -eq $global:configData) {
        if (Test-Path $configFile) {
            try { $global:configData = Get-Content $configFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch {}
        }
    }
    if ($null -eq $global:configData) {
        Log-Message "[AUDITORIA ERRO] Arquivo config.json nao pode ser carregado."
        return
    }
    
    $pref = $global:configData.Preferences
    $task = $global:configData.Tasks | Where-Object { $_.TaskName -eq $TaskName } | Select-Object -First 1
    if ($null -eq $task) {
        $task = $global:configData.Tasks | Select-Object -First 1
    }
    if ($null -eq $task) {
        Log-Message "[AUDITORIA ERRO] Nenhuma tarefa encontrada para auditoria."
        return
    }
    
    $clientName = if (-not [string]::IsNullOrWhiteSpace($pref.ClientName)) { $pref.ClientName } else { "CLIENTE SISMOTEL" }
    $anyDeskId = if (-not [string]::IsNullOrWhiteSpace($pref.AnyDeskId)) { $pref.AnyDeskId } else { "N&atilde;o configurado" }
    $teamViewerId = if (-not [string]::IsNullOrWhiteSpace($pref.TeamViewerId)) { $pref.TeamViewerId } else { "N&atilde;o configurado" }
    $gapThreshold = if ($null -ne $pref.AuditGapWarningThreshold -and $pref.AuditGapWarningThreshold -gt 0) { [int]$pref.AuditGapWarningThreshold } else { 200000 }
    
    # 1. Ferramentas Firebird
    $gbakExe = $task.GbakPath
    if (-not (Test-Path $gbakExe)) {
        $autoGbak = "C:\Program Files\Firebird\Firebird_2_5\bin\gbak.exe"
        if (Test-Path $autoGbak) { $gbakExe = $autoGbak }
        else {
            $autoGbak86 = "C:\Program Files (x86)\Firebird\Firebird_2_5\bin\gbak.exe"
            if (Test-Path $autoGbak86) { $gbakExe = $autoGbak86 }
        }
    }
    $fbBinDir = Split-Path -Parent $gbakExe
    $gfixExe = Join-Path $fbBinDir "gfix.exe"
    $gstatExe = Join-Path $fbBinDir "gstat.exe"
    
    if (-not (Test-Path $gstatExe)) {
        Log-Message "[AUDITORIA ERRO] gstat.exe nao localizado em: $fbBinDir"
        return
    }
    
    # 2. ETAPA 1: DIAGNOSTICO DE CABECALHO E TRANSACAO NO BANCO ATIVO (gstat -h, Zero Locks, 0.05s)
    $liveDb = $task.DatabasePath
    if (-not (Test-Path $liveDb)) {
        if ($liveDb -like "C:\*" -and (Test-Path ("D:" + $liveDb.Substring(2)))) { $liveDb = "D:" + $liveDb.Substring(2) }
        elseif ($liveDb -like "D:\*" -and (Test-Path ("C:" + $liveDb.Substring(2)))) { $liveDb = "C:" + $liveDb.Substring(2) }
    }
    
    Log-Message "[AUDITORIA] 1/4 - Analisando transacoes ativas via gstat -h (Zero Locks, 100% online)..."
    $gstatOut = & "$gstatExe" -h "$liveDb" 2>&1 | Out-String
    
    $oldestTrans = 0
    $nextTrans = 0
    if ($gstatOut -match 'Oldest transaction\s+(\d+)') { $oldestTrans = [long]$matches[1] }
    if ($gstatOut -match 'Next transaction\s+(\d+)') { $nextTrans = [long]$matches[1] }
    
    $transGap = $nextTrans - $oldestTrans
    $isGapAlert = ($transGap -ge $gapThreshold)
    $is32BitAlert = ($nextTrans -ge 1500000000)
    
    Log-Message "[AUDITORIA] Metricas de Transacao: Oldest=$oldestTrans | Next=$nextTrans | Transaction Gap=$transGap (Alerta: $gapThreshold)"
    if ($isGapAlert) {
        Log-Message "[AUDITORIA ALERTA] Transaction Gap elevado ($transGap)! Acumulo de transacoes sem commit detectado."
    }
    if ($is32BitAlert) {
        Log-Message "[AUDITORIA CRITICO] Next Transaction proximo ao limite de 32 bits ($nextTrans)! Executar fixtranslimit."
    }
    
    # 3. ETAPA 2: LOCALIZA ULTIMO BACKUP PARA RESTAURACAO EM SANDBOX
    Log-Message "[AUDITORIA] 2/4 - Localizando ultimo arquivo de backup valido para teste fisico..."
    $searchDirs = @()
    if ($null -ne $task.Destinations) {
        foreach ($d in $task.Destinations) {
            if (-not [string]::IsNullOrWhiteSpace($d) -and -not $d.StartsWith("\\") -and (Test-Path $d)) {
                $searchDirs += $d
            }
        }
    }
    if (Test-Path "D:\BKP_SISMOTEL") { $searchDirs += "D:\BKP_SISMOTEL" }
    if (Test-Path "C:\BKP_SISMOTEL") { $searchDirs += "C:\BKP_SISMOTEL" }
    $searchDirs = $searchDirs | Select-Object -Unique
    
    $latestZip = $null
    foreach ($sd in $searchDirs) {
        $zips = Get-ChildItem -Path $sd -Filter "*.zip" -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
        if ($zips.Count -gt 0) {
            $latestZip = $zips[0]
            break
        }
    }
    
    if ($null -eq $latestZip) {
        Log-Message "[AUDITORIA AVISO] Nenhum arquivo .ZIP de backup localizado para teste fisico. Validacao fisica ignorada."
        Update-ConfigAuditDate -NewDate (Get-Date -Format "yyyy-MM-dd")
        return
    }
    
    Log-Message "[AUDITORIA] Arquivo de backup selecionado: $($latestZip.FullName) ($([math]::Round($latestZip.Length / 1MB, 2)) MB)"
    
    # 4. ETAPA 3: SELECAO INTELIGENTE DO DISCO SANDBOX (C:, D: ou E:)
    $dbSizeMB = 0
    try {
        $dbSizeMB = [math]::Round(((Get-Item $liveDb -ErrorAction Stop).Length / 1MB), 2)
    } catch {
        Log-Message "[AUDITORIA AVISO] Nao foi possivel obter tamanho do banco ($liveDb): $_. Usando estimativa do ZIP."
        $dbSizeMB = [math]::Round(($latestZip.Length / 1MB) * 1.3, 2)
    }
    $sandboxInfo = Get-OptimalSandboxDir -DbPath $liveDb -DbSizeMB $dbSizeMB -ConfiguredDestinations $task.Destinations
    
    if ($sandboxInfo.Status -eq "INSUFFICIENT_SPACE") {
        Log-Message "[AUDITORIA AVISO] Espaco em disco insuficiente para criacao da sandbox (Minimo: $($sandboxInfo.RequiredMB) MB). Restauracao fisica ignorada para proteger o servidor."
        Update-ConfigAuditDate -NewDate (Get-Date -Format "yyyy-MM-dd")
        return
    }
    
    $sandboxDir = $sandboxInfo.Path
    Log-Message "[AUDITORIA] 3/4 - Ambiente Sandbox Isolado: $($sandboxInfo.Drive) | Caminho: $sandboxDir | Espaco Livre: $($sandboxInfo.FreeMB) MB"
    
    if (-not (Test-Path $sandboxDir)) {
        New-Item -ItemType Directory -Path $sandboxDir -Force | Out-Null
    } else {
        Get-ChildItem -Path $sandboxDir -Filter "audit_sandbox*.fdb" | ForEach-Object {
            Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
        }
    }
    
    $sandboxDbPath = Join-Path $sandboxDir "audit_sandbox_$(Get-Date -Format 'yyyyMMdd_HHmmss').fdb"
    $extractedFbkPath = $null
    $recordErrors = 0
    $pageErrors = 0
    $gfixLog = ""
    $auditSuccess = $false
    
    try {
        # Extrai FBK do ZIP
        Log-Message "[AUDITORIA] Extraindo .FBK do backup para o sandbox..."
        try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue } catch {}
        
        $zip = [System.IO.Compression.ZipFile]::OpenRead($latestZip.FullName)
        $fbkEntry = $zip.Entries | Where-Object { $_.Name.EndsWith(".fbk", [StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1
        if ($null -eq $fbkEntry) {
            throw "Arquivo .FBK nao encontrado dentro de $($latestZip.Name)"
        }
        
        $extractedFbkPath = Join-Path $sandboxDir $fbkEntry.Name
        if (Test-Path $extractedFbkPath) { Remove-Item $extractedFbkPath -Force -ErrorAction SilentlyContinue }
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($fbkEntry, $extractedFbkPath, $true)
        $zip.Dispose()
        $zip = $null
        
        Log-Message "[AUDITORIA] Arquivo FBK extraido ($([math]::Round((Get-Item $extractedFbkPath).Length / 1MB, 2)) MB). Iniciando restauracao de teste (gbak -c -v)..."
        
        if (Test-Path $sandboxDbPath) { Remove-Item $sandboxDbPath -Force -ErrorAction SilentlyContinue }
        
        $dbUser = if (-not [string]::IsNullOrWhiteSpace($task.DbUser)) { $task.DbUser } else { "SYSDBA" }
        $dbPassRaw = if (-not [string]::IsNullOrWhiteSpace($task.DbPassword)) { $task.DbPassword } else { "masterkey" }
        $dbPass = Unprotect-String $dbPassRaw
        
        $gbakErrLog = Join-Path $sandboxDir "gbak_restore_err.log"
        $gbakArgs = @("-rep", "-v", "-user", $dbUser, "-password", $dbPass, "`"$extractedFbkPath`"", "`"$sandboxDbPath`"")
        $procGbak = Start-ProcessThrottled -FilePath $gbakExe -ArgumentList $gbakArgs -StdErrFile $gbakErrLog -TimeoutSeconds 7200
        
        # Exclui o FBK extraido imediatamente para liberar espaco
        if (Test-Path $extractedFbkPath) { Remove-Item $extractedFbkPath -Force -ErrorAction SilentlyContinue; $extractedFbkPath = $null }
        
        if ($procGbak.ExitCode -ne 0 -or -not (Test-Path $sandboxDbPath)) {
            $restoreErr = if (Test-Path $gbakErrLog) { Get-Content $gbakErrLog -Raw } else { "ExitCode $($procGbak.ExitCode)" }
            throw "Falha ao restaurar banco na sandbox: $restoreErr"
        }
        
        Log-Message "[AUDITORIA] Banco restaurado na sandbox com sucesso ($([math]::Round((Get-Item $sandboxDbPath).Length / 1MB, 2)) MB). Arquivo de backup 100% legivel!"
        
        # 5. ETAPA 4: VALIDACAO PROFUNDA VIA GFIX (-v -full -no_update)
        Log-Message "[AUDITORIA] 4/4 - Executando gfix -v -full -no_update no banco de sandbox isolado..."
        $gfixArgs = @("-v", "-full", "-no_update", "-user", $dbUser, "-password", $dbPass, "`"$sandboxDbPath`"")
        
        $gfixErrFile = Join-Path $sandboxDir "gfix_validation.log"
        $gfixOutFile = Join-Path $sandboxDir "gfix_out.log"
        $procGfix = Start-ProcessThrottled -FilePath $gfixExe -ArgumentList $gfixArgs -StdErrFile $gfixErrFile -StdOutFile $gfixOutFile -TimeoutSeconds 3600
        
        $gfixLog = ""
        if (Test-Path $gfixErrFile) { $gfixLog += Get-Content $gfixErrFile -Raw }
        if (Test-Path $gfixOutFile) { $gfixLog += Get-Content $gfixOutFile -Raw }
        
        # Extrai contagem de erros
        if ($gfixLog -match 'Number of record level errors\s*:\s*(\d+)') {
            $recordErrors = [int]$matches[1]
        }
        if ($gfixLog -match 'Number of database page errors\s*:\s*(\d+)') {
            $pageErrors = [int]$matches[1]
        }
        
        $hasCorruptionKeywords = ($gfixLog -match 'checksum error' -or $gfixLog -match 'wrong page type' -or $gfixLog -match 'corrupt')
        if ($hasCorruptionKeywords -and $pageErrors -eq 0) {
            $pageErrors = 1
        }
        
        Log-Message "[AUDITORIA] Resultado da Verificacao Fisica: Record Errors = $recordErrors | Page Errors = $pageErrors"
        # Politica MEC: Notifica somente se houver corrupcao fisica real (Record Errors > 0 ou Page Errors > 0).
        # Metricas de transacao (Gap/Next) sao medidas e reportadas caso haja erro fisico, mas nao disparam email sozinhas.
        $auditSuccess = ($recordErrors -eq 0 -and $pageErrors -eq 0)
        
    } catch {
        Log-Message "[AUDITORIA ERRO] Excecao durante auditoria em sandbox: $_"
        $recordErrors = 999
        $gfixLog = "Excecao no processo de auditoria: $_"
    } finally {
        # 6. LIMPEZA COMPLETA E GARANTIDA DO AMBIENTE SANDBOX
        Log-Message "[AUDITORIA] Limpando ambiente sandbox temporario..."
        if ($null -ne $zip) { try { $zip.Dispose() } catch {} }
        if ($null -ne $extractedFbkPath -and (Test-Path $extractedFbkPath)) {
            Remove-Item $extractedFbkPath -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path $sandboxDbPath) {
            Remove-Item $sandboxDbPath -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path $sandboxDir) {
            Remove-Item $sandboxDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        Log-Message "[AUDITORIA] Limpeza da sandbox concluida com 0 bytes residuais em disco."
    }
    
    # 7. REGISTRO E DISPARO DE NOTIFICACAO (POLITICA ZERO SPAM)
    Update-ConfigAuditDate -NewDate (Get-Date -Format "yyyy-MM-dd")
    
    if ($auditSuccess) {
        if ($isGapAlert) {
            Log-Message "[AUDITORIA 100% SUCESSO] Banco de dados Sismotel FISICAMENTE INTEGRO! 0 erros de registro, 0 erros de paginas. Transaction Gap em $transGap (notificacao de e-mail silenciada)."
        } else {
            Log-Message "[AUDITORIA 100% SUCESSO] Banco de dados Sismotel FISICAMENTE INTEGRO! 0 erros de registro, 0 erros de paginas, Transaction Gap normal ($transGap)."
        }
        Log-Message "[AUDITORIA ZERO SPAM] Operacao 100% silenciosa no e-mail conforme politica corporativa."
    } else {
        Log-Message "[AUDITORIA ALERTA CRITICO] Corrupcao fisica detectada no Firebird! Record Errors: $recordErrors | Page Errors: $pageErrors. Disparando notificacao de emergencia para equipe tecnica..."
        Send-AuditAlertNotification -ClientName $clientName -AnyDeskId $anyDeskId -TeamViewerId $teamViewerId -DbPath $liveDb -RecordErrors $recordErrors -PageErrors $pageErrors -TransactionGap $transGap -NextTransaction $nextTrans -AuditLogSnippet $gfixLog
    }
    Log-Message "--------------------------------------------------------------------------------"
}

# INTERCEPTADOR: EXECUCAO DE AUDITORIA SOB DEMANDA (-RunAuditOnly)
if ($RunAuditOnly) {
    Log-Message "======================================================"
    Log-Message "SOLICITACAO RECEBIDA: Executando Diagnostico de Integridade Sob Demanda (-RunAuditOnly)..."
    Invoke-DatabaseHealthAudit -TaskName $TaskName -Force:$ForceAudit
    Log-Message "Diagnostico de integridade concluido com sucesso."
    Log-Message "======================================================"
    exit 0
}

# INTERCEPTADOR: VERIFICACAO DE SAUDE DO BACKUP EXTERNO (-CheckExternalHealth)
if ($CheckExternalHealth) {
    Log-Message "======================================================"
    Log-Message "MONITOR DE BACKUP: Verificando se os destinos possuem backup recente (-CheckExternalHealth)..."

    # Este monitor roda por conta propria (tarefa agendada horaria), INDEPENDENTE de o
    # backup ter rodado ou nao. E ele que cobre o caso critico: servidor desligado,
    # servico parado ou rotina travada -- situacoes em que a rotina de backup nunca
    # chega a avaliar os destinos e, sem este monitor, ninguem seria avisado.
    if ($null -eq $global:configData) {
        if (Test-Path $configFile) {
            try { $global:configData = Get-Content $configFile -Raw -Encoding UTF8 | ConvertFrom-Json }
            catch { Log-Message "ERRO: config.json ilegivel: $_"; exit 1 }
        }
    }
    if ($null -eq $global:configData -or $null -eq $global:configData.Tasks) {
        Log-Message "ERRO: nenhuma tarefa configurada para monitorar."
        exit 1
    }

    $checked = 0
    foreach ($t in $global:configData.Tasks) {
        if ($null -ne $t.Enabled -and [bool]$t.Enabled -eq $false) {
            Log-Message "Tarefa '$($t.TaskName)' esta pausada. Monitoramento ignorado."
            continue
        }
        if ($null -eq $t.Destinations -or $t.Destinations.Count -eq 0) { continue }

        # Resolve unidade mapeada (Z:\) para UNC, pois sob a conta SYSTEM ela nao existe
        $dests = @()
        foreach ($d in $t.Destinations) {
            if ([string]::IsNullOrWhiteSpace($d)) { continue }
            $dests += (Resolve-MappedDrivePath $d.Trim())
        }
        if ($dests.Count -eq 0) { continue }

        Log-Message "Monitorando tarefa '$($t.TaskName)' -> $($dests -join ' | ')"
        Test-ExternalDestinationsHealth -TaskName $t.TaskName -Destinations $dests
        $checked++
    }

    Log-Message "Monitor concluido. $checked tarefa(s) verificada(s)."
    Log-Message "======================================================"
    exit 0
}

# ==============================================================================
# CAMADA OFICIAL DE AUTO-UPDATE EM NUVEM (MEC LIVEUPDATE VIA GITHUB)
# ==============================================================================
function Invoke-MecLiveUpdate {
    param (
        [switch]$Force = $false
    )
    
    $engineVersion = "2.2.0"
    $webClient = $null
    
    try {
        if ($null -eq $global:configData -or $null -eq $global:configData.Preferences) {
            if (Test-Path $configFile) {
                try { $global:configData = Get-Content $configFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch {}
            }
        }
        $pref = if ($null -ne $global:configData) { $global:configData.Preferences } else { $null }
        
        $enableAutoUpdate = if ($null -ne $pref -and $null -ne $pref.AutoUpdateEnabled) { [bool]$pref.AutoUpdateEnabled } else { $true }
        if (-not $enableAutoUpdate -and -not $Force) {
            Log-Message "[LIVEUPDATE] Auto-Update desativado nas preferencias locais."
            return
        }
        
        $updateUrl = if ($null -ne $pref -and -not [string]::IsNullOrWhiteSpace($pref.AutoUpdateUrl)) {
            $pref.AutoUpdateUrl
        } else {
            "https://raw.githubusercontent.com/digaooliveira96-debug/fibs-shield-updates/main/version.json"
        }
        
        $todayStr = Get-Date -Format "yyyy-MM-dd"
        $fibsStateFile = Join-Path $scriptDir "fibs_state.json"
        $fibsState = $null
        if (Test-Path $fibsStateFile) {
            try { $fibsState = Get-Content $fibsStateFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch {}
        }
        if ($null -eq $fibsState) {
            $fibsState = [PSCustomObject]@{ WelcomeEmailSent = $false; LastUpdateCheck = "" }
        }
        
        if (-not $Force -and ($fibsState.LastUpdateCheck -eq $todayStr)) {
            return
        }
        
        Log-Message "[LIVEUPDATE] Verificando atualizacoes online no canal oficial GitHub..."
        
        # Garante suporte a TLS 1.2 para comunicacao segura com o GitHub
        try {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
        } catch {}
        
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "MEC-Shield-LiveUpdate/$engineVersion")
        
        # Le manifesto remoto (version.json)
        $manifestJson = $webClient.DownloadString($updateUrl)
        $manifest = $manifestJson | ConvertFrom-Json
        
        $fibsState.LastUpdateCheck = $todayStr
        try { $fibsState | ConvertTo-Json -Depth 5 | Set-Content $fibsStateFile -Encoding UTF8 } catch {}
        
        if ($null -eq $manifest -or [string]::IsNullOrWhiteSpace($manifest.version)) {
            Log-Message "[LIVEUPDATE AVISO] Manifesto de versao invalido recebido do servidor."
            return
        }
        
        $remoteVer = [System.Version]$manifest.version
        $localVer = [System.Version]$engineVersion
        
        if ($remoteVer -le $localVer -and -not $Force) {
            Log-Message "[LIVEUPDATE] FIBS esta atualizado na ultima versao ($engineVersion). Nenhuma acao necessaria."
            return
        }
        
        Log-Message "[LIVEUPDATE] Nova versao detectada no GitHub: v$($manifest.version) (Instalada: v$engineVersion)! Baixando..."
        $downloadUrl = $manifest.downloadUrl
        if ([string]::IsNullOrWhiteSpace($downloadUrl)) {
            $downloadUrl = "https://raw.githubusercontent.com/digaooliveira96-debug/fibs-shield-updates/main/backup_engine.ps1"
        }
        
        # Prepara pasta temporaria isolada
        $tempDir = Join-Path $scriptDir "temp"
        if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir -Force | Out-Null }
        $stageFile = Join-Path $tempDir "backup_engine_stage.ps1"
        if (Test-Path $stageFile) { Remove-Item $stageFile -Force -ErrorAction SilentlyContinue }
        
        # Baixa o script da nova versao
        $webClient.DownloadFile($downloadUrl, $stageFile)
        
        if (-not (Test-Path $stageFile)) {
            throw "Falha ao gravar arquivo temporario baixado em $stageFile"
        }
        
        $stageItem = Get-Item $stageFile
        if ($stageItem.Length -lt 50KB -or $stageItem.Length -gt 5MB) {
            throw "Tamanho suspeito do arquivo baixado ($($stageItem.Length) bytes). Abortando para proteger instalacao."
        }
        
        $stageContent = Get-Content $stageFile -Raw -Encoding UTF8
        if (-not $stageContent.Contains("MEC Shield Enterprise") -or -not $stageContent.Contains("Invoke-TaskBackup")) {
            throw "Assinatura essencial do FIBS ausente no arquivo baixado (possivel resposta HTTP de erro)."
        }
        
        # GATE DE SEGURANCA: Analise lexica e sintatica do script baixado
        $parseErrors = $null
        $tokens = [System.Management.Automation.PSParser]::Tokenize($stageContent, [ref]$parseErrors)
        if ($null -ne $parseErrors -and $parseErrors.Count -gt 0) {
            throw "O arquivo baixado contem $($parseErrors.Count) erro(s) de sintaxe PowerShell. Abortando com seguranca."
        }
        
        # Backup garantido do script atual (.bak)
        $liveEngineFile = Join-Path $scriptDir "backup_engine.ps1"
        $bakEngineFile = Join-Path $scriptDir "backup_engine.ps1.bak"
        Copy-Item $liveEngineFile $bakEngineFile -Force
        
        # Swap atomico
        Move-Item $stageFile $liveEngineFile -Force
        
        Log-Message "[LIVEUPDATE 100% SUCESSO] Motor FIBS atualizado com sucesso para a versao v$($manifest.version)!"
        Log-Message "[LIVEUPDATE] Backup da versao anterior salvo em: $bakEngineFile"
        Log-Message "[LIVEUPDATE] As proximas rotinas rodarao com o novo motor automaticamente."
        
    } catch {
        Log-Message "[LIVEUPDATE] Checagem de atualizacoes concluida sem alteracao no sistema: $_"
    } finally {
        if ($null -ne $webClient) { $webClient.Dispose() }
    }
}

# INTERCEPTADOR: VERIFICACAO DE ATUALIZACAO SOB DEMANDA (-CheckUpdateOnly)
if ($CheckUpdateOnly) {
    Log-Message "======================================================"
    Log-Message "SOLICITACAO RECEBIDA: Verificando atualizacoes online sob demanda (-CheckUpdateOnly)..."
    Invoke-MecLiveUpdate -Force:$ForceUpdate
    Log-Message "Verificacao de atualizacoes concluida."
    Log-Message "======================================================"
    exit 0
}

# 2. SHIELD DE CONCORRENCIA: Arquivo de Lock para impedir duas rotinas concorrendo no banco
$lockFile = Join-Path $scriptDir "backup_execution.lock"
$lockAcquired = $false
$maxLockWaitSec = 300 # Aguarda ate 5 minutos caso outra tarefa esteja terminando

for ($w = 0; $w -lt $maxLockWaitSec; $w += 5) {
    if (-not (Test-Path $lockFile)) {
        try {
            $lockContent = "$TaskName | PID:$PID | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            [System.IO.File]::WriteAllText($lockFile, $lockContent)
            $lockAcquired = $true
            break
        } catch {}
    } else {
        try {
            $existingLock = Get-Content $lockFile -Raw -ErrorAction SilentlyContinue
            if ($existingLock -match 'PID:(\d+)') {
                $ownerPid = [int]$matches[1]
                $ownerProc = Get-Process -Id $ownerPid -ErrorAction SilentlyContinue
                if ($null -eq $ownerProc) {
                    Log-Message "Aviso: Lock orfao anterior detectado (PID $ownerPid inativo). Liberando lock..."
                    Remove-Item $lockFile -Force -ErrorAction SilentlyContinue
                    continue
                }
            }
        } catch {}

        Log-Message "Aviso: Outra tarefa de backup em andamento ($existingLock). Aguardando liberacao ($w/$maxLockWaitSec s)..."
        Start-Sleep -Seconds 5
    }
}

if (-not $lockAcquired) {
    Log-Message "ALERTA DE PROTECAO: Outra rotina de backup ainda estava em andamento apos 5 minutos. Para proteger o banco em producao, esta execucao foi ignorada com seguranca."
    exit 0
}

# Trap global para capturar excecoes criticas
trap {
    try {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $errLine = "[$timestamp] [$TaskName] ERRO CRITICO NAO TRATADO: $_"
        Write-Output $errLine
        if ($null -ne $logFile) { Add-Content -Path $logFile -Value $errLine -Encoding UTF8 -ErrorAction SilentlyContinue }
        Send-BackupNotification -Status "FALHA" -SubjectInfo "Erro Critico na Tarefa $TaskName" -BodyDetails $errLine
    } catch {}
    
    # Limpeza tolerante a nulo: numa falha precoce (ex.: banco inacessivel) estas
    # variaveis ainda nao existem, e um Test-Path $null lancava excecao aqui dentro
    # do proprio trap, impedindo o "exit 1" de ser alcancado e mascarando o codigo
    # de saida que o startup_guard.ps1 registra.
    foreach ($tmp in @($lockFile, $tempFbk, $tempZip, $gbakLog)) {
        if (-not [string]::IsNullOrWhiteSpace($tmp)) {
            try { if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue } } catch {}
        }
    }
    exit 1
}

# Rotacao de logs se o arquivo for maior que 5MB
if ((Test-Path $logFile) -and (Get-Item $logFile).Length -gt 5MB) {
    $archiveName = $logFile -replace '\.txt$', "_$(Get-Date -f 'yyyyMMdd_HHmmss').txt"
    try {
        Rename-Item -Path $logFile -NewName (Split-Path $archiveName -Leaf) -Force -ErrorAction SilentlyContinue
    } catch {}
}

Log-Message "======================================================"
Log-Message "Iniciando rotina de backup (Modo Resiliente 24/7 - Blindado)..."
$global:routineTimer = [System.Diagnostics.Stopwatch]::StartNew()
$global:gbakTimer    = New-Object System.Diagnostics.Stopwatch
$global:zipTimer     = New-Object System.Diagnostics.Stopwatch
$fbkSizeMB           = 0
$zipSizeMB           = 0

if (-not (Test-Path $configFile)) {
    Log-Message "ERRO: Arquivo config.json nao encontrado em: $configFile"
    if (Test-Path $lockFile) { Remove-Item $lockFile -Force -ErrorAction SilentlyContinue }
    exit 1
}

# Carrega as configuracoes
try {
    $global:configData = Get-Content $configFile -Raw -Encoding UTF8 | ConvertFrom-Json
} catch {
    Log-Message "ERRO ao decodificar config.json: $_"
    if (Test-Path $lockFile) { Remove-Item $lockFile -Force -ErrorAction SilentlyContinue }
    exit 1
}

# Converte credenciais em texto puro para forma criptografada (uma unica vez por servidor)
Convert-PlainPasswordsInConfig
if (Test-Path $configFile) {
    try { $global:configData = Get-Content $configFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch {}
}

# --- ENVIO DO EMAIL DE BOAS VINDAS NA PRIMEIRA EXECUCAO ---
$fibsStateFile = Join-Path $scriptDir "fibs_state.json"
$fibsState = $null
if (Test-Path $fibsStateFile) {
    try { $fibsState = Get-Content $fibsStateFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch {}
}
if ($null -eq $fibsState) {
    $fibsState = [PSCustomObject]@{ WelcomeEmailSent = $false }
}
if (-not $fibsState.WelcomeEmailSent -and $null -ne $global:configData.Preferences) {
    $p = $global:configData.Preferences
    if (-not [string]::IsNullOrWhiteSpace($p.SmtpServer) -and -not [string]::IsNullOrWhiteSpace($p.RecipientEmail)) {
        Log-Message "Primeira execucao detectada. Enviando e-mail de Boas-Vindas..."
        Send-WelcomeEmail
        $fibsState.WelcomeEmailSent = $true
        try { $fibsState | ConvertTo-Json -Depth 5 | Set-Content $fibsStateFile -Encoding UTF8 } catch {}
    }
}
# -----------------------------------------------------------

$networkTrackerFile = Join-Path $scriptDir "network_tracker.json"
# Localiza a tarefa pelo nome
$task = $null
foreach ($t in $global:configData.Tasks) {
    if ($t.TaskName -eq $TaskName) {
        $task = $t
        break
    }
}

if ($null -eq $task) {
    $errMsg = "ERRO CRITICO: Tarefa '$TaskName' nao configurada no config.json!"
    Log-Message $errMsg
    Send-BackupNotification -Status "FALHA" -SubjectInfo "Tarefa Nao Encontrada ($TaskName)" -BodyDetails $errMsg
    if (Test-Path $lockFile) { Remove-Item $lockFile -Force -ErrorAction SilentlyContinue }
    exit 1
}

# Verificacao de Tarefa Desativada (Pausada)
if ($null -ne $task.Enabled -and [bool]$task.Enabled -eq $false) {
    Log-Message "AVISO: A tarefa '$TaskName' esta DESATIVADA (Pausada) pelo usuario. Execucao cancelada com seguranca."
    if (Test-Path $lockFile) { Remove-Item $lockFile -Force -ErrorAction SilentlyContinue }
    exit 0
}

# --- GUARDA ANTI-DUPLICIDADE ---
# A mesma tarefa e disparada por DOIS caminhos no mesmo minuto: o timer do
# MEC_Shield_Service e a tarefa agendada do Windows (FIBS_Backup_<nome>). O lock so
# protege enquanto a primeira ainda roda; quando a rotina termina rapido (bancos
# pequenos), a segunda pegava o lock e refazia o backup inteiro, dobrando o I/O e
# consumindo dois numeros de sequencia -- o que reduzia pela metade a retencao real.
# Execucao manual (-Manual, botao "Backup Agora") nunca e bloqueada.
$lastRunFile = Join-Path $scriptDir "last_run.json"
$dedupeMinutes = 10
if (-not $Manual) {
    try {
        if (Test-Path $lastRunFile) {
            $lastRuns = Get-Content $lastRunFile -Raw -Encoding UTF8 | ConvertFrom-Json
            $prev = $lastRuns.$TaskName
            if (-not [string]::IsNullOrWhiteSpace($prev)) {
                $minutosDesde = ((Get-Date) - [DateTime]::Parse($prev)).TotalMinutes
                if ($minutosDesde -ge 0 -and $minutosDesde -lt $dedupeMinutes) {
                    Log-Message "DISPARO DUPLICADO IGNORADO: a tarefa '$TaskName' ja concluiu com sucesso ha $([Math]::Round($minutosDesde,1)) minuto(s) (janela de $dedupeMinutes min). Execucao redundante cancelada."
                    if (Test-Path $lockFile) { Remove-Item $lockFile -Force -ErrorAction SilentlyContinue }
                    exit 0
                }
            }
        }
    } catch {
        Log-Message "Aviso ao ler o registro de ultima execucao: $_"
    }
}

$gbakPath            = $task.GbakPath
$gfixPathConfig      = $task.GfixPath
$dbPath              = $task.DatabasePath
$dbUser              = if ([string]::IsNullOrWhiteSpace($task.DbUser)) { "SYSDBA" } else { $task.DbUser }
$dbPassRaw          = if ([string]::IsNullOrWhiteSpace($task.DbPassword)) { "masterkey" } else { $task.DbPassword }
$dbPassword          = Unprotect-String $dbPassRaw
$destinations        = $task.Destinations
$keepBackupsCount    = if ($task.KeepBackupsCount -gt 0) { [int]$task.KeepBackupsCount } else { 30 }
$retryCount          = if ($task.RetryCount -gt 0) { [int]$task.RetryCount } else { 3 }
$retryInterval       = if ($task.RetryIntervalSeconds -gt 0) { [int]$task.RetryIntervalSeconds } else { 30 }
$noGarbageCollection = if ($null -ne $task.NoGarbageCollection) { [bool]$task.NoGarbageCollection } else { $true }
$convertExternal     = if ($null -ne $task.ConvertExternal) { [bool]$task.ConvertExternal } else { $true }
$runGfixSweep        = if ($null -ne $task.RunGfixSweep) { [bool]$task.RunGfixSweep } else { $false }
$runGfixValidate     = if ($null -ne $task.RunGfixValidate) { [bool]$task.RunGfixValidate } else { $false }
$networkUser         = $task.NetworkUser
$networkPassword     = Unprotect-String $task.NetworkPassword

# --- FASE 1: AUTO-RECUPERACAO E ESPERA DE PRONTIDAO NO BOOT ---
$maxBootWaitSec = 45
$bootWaited = 0

# 1.1 Garante que o servico Firebird esteja em execucao e configurado para Automatico
$fbServerSrv = Get-Service -Name *firebird* -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "Server" }
if ($null -ne $fbServerSrv) {
    try { Set-Service -Name $fbServerSrv.Name -StartupType Automatic -ErrorAction SilentlyContinue } catch {}
    if ($fbServerSrv.Status -ne "Running") {
        Log-Message "Servico do Firebird ($($fbServerSrv.Name)) detectado como parado. Iniciando servico..."
        try { Start-Service $fbServerSrv.Name -ErrorAction SilentlyContinue } catch {}
        
        while ($bootWaited -lt $maxBootWaitSec) {
            Start-Sleep -Seconds 3
            $bootWaited += 3
            $currentStatus = (Get-Service $fbServerSrv.Name -ErrorAction SilentlyContinue).Status
            if ($currentStatus -eq "Running") {
                Log-Message "Servico do Firebird iniciado e pronto para conexoes."
                break
            }
        }
    }
}

# 1.2 Valida existencia do gbak.exe
# Se GbakPath vier vazio no config.json, Test-Path $null lancava excecao e abortava
# a rotina antes de chegar na auto-deteccao logo abaixo. Normaliza para string vazia.
if ([string]::IsNullOrWhiteSpace($gbakPath)) { $gbakPath = "" }
if ([string]::IsNullOrWhiteSpace($dbPath))   { $dbPath = "" }
if ($gbakPath -eq "" -or -not (Test-Path $gbakPath)) {
    $autoGbak = Join-Path "C:\Program Files\Firebird\Firebird_2_5\bin" "gbak.exe"
    if (Test-Path $autoGbak) {
        $gbakPath = $autoGbak
    } else {
        $autoGbak86 = Join-Path "C:\Program Files (x86)\Firebird\Firebird_2_5\bin" "gbak.exe"
        if (Test-Path $autoGbak86) { $gbakPath = $autoGbak86 }
    }
}

if ($gbakPath -eq "" -or -not (Test-Path $gbakPath)) {
    $errMsg = "ERRO CRITICO: gbak.exe nao encontrado. Caminho configurado: '$gbakPath'. Tambem nao foi localizado nas pastas padrao do Firebird 2.5."
    Log-Message $errMsg
    Send-BackupNotification -Status "FALHA" -SubjectInfo "gbak.exe Nao Encontrado ($TaskName)" -BodyDetails $errMsg
    if (Test-Path $lockFile) { Remove-Item $lockFile -Force -ErrorAction SilentlyContinue }
    exit 1
}

# 1.3 Aguarda disponibilidade do arquivo do Banco de Dados (com auto-deteccao entre C: e D:)
$dbExists = $false
for ($i = 1; $i -le 10; $i++) {
    if ($dbPath -ne "" -and (Test-Path $dbPath)) { $dbExists = $true; break }
    
    # Se o banco nao estiver no caminho configurado, tenta alternar entre C: e D:
    $altPaths = @()
    if ($dbPath -like "C:\*") {
        $altPaths += "D:" + $dbPath.Substring(2)
        $altPaths += "D:\Microtecs\Sismotel\bd\DBSISMOTEL.FDB"
        $altPaths += "D:\Microtecs\Sismotel\bd\SISMOTEL.FDB"
    } elseif ($dbPath -like "D:\*") {
        $altPaths += "C:" + $dbPath.Substring(2)
        $altPaths += "C:\Microtecs\Sismotel\bd\DBSISMOTEL.FDB"
        $altPaths += "C:\Microtecs\Sismotel\bd\SISMOTEL.FDB"
    } else {
        $altPaths += "C:\Microtecs\Sismotel\bd\DBSISMOTEL.FDB"
        $altPaths += "D:\Microtecs\Sismotel\bd\DBSISMOTEL.FDB"
    }

    foreach ($alt in $altPaths) {
        if (Test-Path $alt) {
            Log-Message "Aviso: Banco nao encontrado em '$dbPath', mas localizado com sucesso em: $alt"
            $dbPath = $alt
            $dbExists = $true
            break
        }
    }
    if ($dbExists) { break }

    Log-Message "Aguardando banco de dados ficar acessivel ($i/10): $dbPath ..."
    Start-Sleep -Seconds 3
}

if (-not $dbExists) {
    $errMsg = "ERRO CRITICO: Banco de dados inacessivel em: $dbPath (e alternativos em C: e D:) apos 10 tentativas."
    Log-Message $errMsg
    Send-BackupNotification -Status "FALHA" -SubjectInfo "Banco Inacessivel ($TaskName)" -BodyDetails $errMsg
    if (Test-Path $lockFile) { Remove-Item $lockFile -Force -ErrorAction SilentlyContinue }
    exit 1
}

$dbSizeMB = [math]::Round(((Get-Item $dbPath).Length / 1MB), 2)
Log-Message "Banco de dados pronto: $dbPath ($dbSizeMB MB)"

# 3. SHIELD DE PARTICIONAMENTO E I/O: Resolucao de destinos e isolamento de disco temporario
$destList = @()
if ($null -ne $destinations) {
    if ($destinations -is [string]) { $destList = @($destinations) } else { $destList = $destinations }
}

$resolvedDestList = @()
foreach ($dest in $destList) {
    if ([string]::IsNullOrWhiteSpace($dest)) { continue }
    $destTrimmed = $dest.Trim()

    # Traducao automatica de unidade mapeada (ex: Z:\... -> \\servidor\pasta\...) para servicos Windows (SYSTEM)
    $destResolved = Resolve-MappedDrivePath $destTrimmed
    if ($destResolved -ne $destTrimmed) {
        Log-Message "Unidade mapeada detectada: '$destTrimmed' resolvida para caminho UNC: '$destResolved'"
        $destTrimmed = $destResolved
    }

    if ($destTrimmed.StartsWith("\\")) {
        # Destino de rede UNC
        $resolvedDestList += $destTrimmed
    } else {
        # Destino local
        $destRoot = [System.IO.Path]::GetPathRoot($destTrimmed)
        if (-not (Test-Path $destRoot)) {
            Log-Message "Aviso: A particao/unidade '$destRoot' nao existe neste computador (sistema com particao unica ou drive ausente)."
            $fallbackDest = "C:\BKP_SISMOTEL"
            if (-not ($resolvedDestList -contains $fallbackDest)) {
                Log-Message "Redirecionando destino local automaticamente para: $fallbackDest"
                $resolvedDestList += $fallbackDest
            }
        } else {
            $resolvedDestList += $destTrimmed
        }
    }
}
if ($resolvedDestList.Count -eq 0) {
    $resolvedDestList += "C:\BKP_SISMOTEL"
}
foreach ($d in $resolvedDestList) {
    if (-not $d.StartsWith("\\") -and -not (Test-Path $d)) {
        try { New-Item -ItemType Directory -Path $d -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
    }
}

$tempDir = $null
$dbDrive = [System.IO.Path]::GetPathRoot($dbPath)

# Procura um destino local em particao diferente do banco para isolamento fisico de gravacao
foreach ($candDest in $resolvedDestList) {
    if ($candDest.StartsWith("\\")) { continue } # NUNCA usar rede para temporario
    $candDrive = [System.IO.Path]::GetPathRoot($candDest)
    if ((Test-Path $candDrive) -and ($candDrive -ne $dbDrive)) {
        $candidateTemp = Join-Path $candDest "temp_backup"
        try {
            if (-not (Test-Path $candidateTemp)) { New-Item -ItemType Directory -Path $candidateTemp -Force | Out-Null }
            $tempDir = $candidateTemp
            break
        } catch {}
    }
}

if ($null -eq $tempDir) {
    $tempDir = Join-Path $scriptDir "temp_backup"
    if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir -Force | Out-Null }
}
Log-Message "Diretorio temporario de processamento I/O: $tempDir"

# 4. SHIELD DE ESPACO EM DISCO: Garante espaco livre suficiente e impede que o disco zere (protegendo o Firebird e o Sismotel)
try {
    $tempRoot = [System.IO.Path]::GetPathRoot($tempDir)
    $drive = New-Object System.IO.DriveInfo($tempRoot)
    $freeSpaceMB = [math]::Round($drive.AvailableFreeSpace / 1MB, 2)
    # Exige espaco para o FBK + ZIP + margem de seguranca (ao menos 1.5x o tamanho do banco ativo)
    $minRequiredMB = [math]::Round($dbSizeMB * 1.5, 2)

    Log-Message "Espaco livre na unidade de processamento ($tempRoot): $freeSpaceMB MB (Minimo seguro exigido: $minRequiredMB MB)"
    if ($freeSpaceMB -lt $minRequiredMB) {
        $errMsg = "ALERTA PREVENTIVO DE SEGURANCA: A unidade '$tempRoot' possui apenas $freeSpaceMB MB livres (necessario ao menos $minRequiredMB MB). Para proteger o banco Firebird e o sistema contra corrupcao por falta de espaco em disco, a rotina foi interrompida preventivamente com 100% de seguranca."
        Log-Message $errMsg
        Send-BackupNotification -Status "FALHA" -SubjectInfo "Espaco em Disco Critico ($TaskName)" -BodyDetails $errMsg -DbPath $dbPath -DbSize "$dbSizeMB"
        if (Test-Path $lockFile) { Remove-Item $lockFile -Force -ErrorAction SilentlyContinue }
        exit 1
    }
} catch {
    Log-Message "Aviso ao verificar espaco em disco: $_"
}

# --- FASE 2: GFIX (OPCIONAL - DESATIVADO POR PADRAO EM ROTINAS HORARIAS) ---
if ($runGfixSweep -or $runGfixValidate) {
    $gfixPath = if (-not [string]::IsNullOrWhiteSpace($gfixPathConfig) -and (Test-Path $gfixPathConfig)) {
        $gfixPathConfig
    } else {
        Join-Path (Split-Path $gbakPath -Parent) "gfix.exe"
    }

    if (Test-Path $gfixPath) {
        if ($runGfixSweep) {
            Log-Message "Executando gfix.exe (-sweep) conforme configurado..."
            try {
                $gfixSweepArgs = "-sweep -user $dbUser -password $dbPassword `"localhost:$dbPath`""
                $pinfoSweep = New-Object System.Diagnostics.ProcessStartInfo
                $pinfoSweep.FileName = $gfixPath
                $pinfoSweep.Arguments = $gfixSweepArgs
                $pinfoSweep.RedirectStandardOutput = $true
                $pinfoSweep.RedirectStandardError = $true
                $pinfoSweep.UseShellExecute = $false
                $pinfoSweep.CreateNoWindow = $true

                $procSweep = [System.Diagnostics.Process]::Start($pinfoSweep)
                try { $procSweep.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal } catch {}
                if ($procSweep.WaitForExit(300000)) {
                    if ($procSweep.ExitCode -eq 0) {
                        Log-Message "gfix -sweep concluido com sucesso."
                    } else {
                        $errOut = $procSweep.StandardError.ReadToEnd()
                        Log-Message "Aviso: gfix -sweep retornou codigo $($procSweep.ExitCode): $errOut"
                    }
                } else {
                    $procSweep.Kill()
                    Log-Message "Aviso: gfix -sweep atingiu timeout de 5 minutos."
                }
            } catch {
                Log-Message "Aviso ao rodar gfix sweep: $_"
            }
        }

        if ($runGfixValidate) {
            Log-Message "Executando gfix.exe (-v) para verificacao de integridade..."
            try {
                $gfixValArgs = "-v -user $dbUser -password $dbPassword `"localhost:$dbPath`""
                $pinfoVal = New-Object System.Diagnostics.ProcessStartInfo
                $pinfoVal.FileName = $gfixPath
                $pinfoVal.Arguments = $gfixValArgs
                $pinfoVal.RedirectStandardOutput = $true
                $pinfoVal.RedirectStandardError = $true
                $pinfoVal.UseShellExecute = $false
                $pinfoVal.CreateNoWindow = $true

                $procVal = [System.Diagnostics.Process]::Start($pinfoVal)
                try { $procVal.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal } catch {}
                if ($procVal.WaitForExit(300000)) {
                    if ($procVal.ExitCode -eq 0) {
                        Log-Message "gfix -v validacao concluida sem erros."
                    } else {
                        $errOut = $procVal.StandardError.ReadToEnd()
                        Log-Message "Aviso: gfix validacao reportou possiveis anomalias: $errOut"
                    }
                } else {
                    $procVal.Kill()
                    Log-Message "Aviso: gfix validacao atingiu timeout."
                }
            } catch {
                Log-Message "Aviso ao rodar gfix validacao: $_"
            }
        }
    }
}

# --- FASE 3: GBAK (BACKUP CONSISTENTE ONLINE - BLINDAGEM PRODUCAO) ---
$basePrefix = if (-not [string]::IsNullOrWhiteSpace($task.BackupFilePrefix)) {
    $task.BackupFilePrefix
} elseif ($TaskName -like "*EXTERNO*") {
    "BKP_EXTERNO"
} else {
    "BKP_SISMOTEL"
}

$seqFile = Join-Path $scriptDir "backup_sequence.json"
$confSeq = if ($null -ne $task.NextSequenceNumber -and $task.NextSequenceNumber -ge 0) { [int]$task.NextSequenceNumber } else { 0 }
$seqNumber = Get-NextBackupSequenceNumber -Prefix $basePrefix -DestinationPaths $resolvedDestList -ConfiguredNextNumber $confSeq -SequenceFilePath $seqFile
$seqStr = "{0:D4}" -f $seqNumber

$tempFbk    = Join-Path $tempDir "$basePrefix-$seqStr.fbk"
$tempZip    = Join-Path $tempDir "$basePrefix-$seqStr.zip"
$gbakLog    = Join-Path $tempDir "gbak_$($TaskName)_log.txt"

# Argumentos GBAK: -b (backup online), -t (transportavel), -g (SEM coleta de lixo / nao trava tabelas ativas)
$gbakArgs = "-b -t"
if ($noGarbageCollection) { $gbakArgs += " -g" }
if ($convertExternal)    { $gbakArgs += " -co" }
$gbakArgs += " -y `"$gbakLog`""
$gbakArgs += " -user $dbUser -password $dbPassword"
$gbakArgs += " `"localhost:$dbPath`" `"$tempFbk`""

$global:gbakTimer.Restart()
Log-Message "Executando gbak.exe (Backup Online Seguro em Prioridade Baixa)..."

$gbakSuccess = $false
$gbakError = ""
for ($attempt = 1; $attempt -le $retryCount; $attempt++) {
    try {
        if (Test-Path $tempFbk) { Remove-Item $tempFbk -Force -ErrorAction SilentlyContinue }
        if (Test-Path $gbakLog) { Remove-Item $gbakLog -Force -ErrorAction SilentlyContinue }

        $pinfo = New-Object System.Diagnostics.ProcessStartInfo
        $pinfo.FileName = $gbakPath
        $pinfo.Arguments = $gbakArgs
        $pinfo.RedirectStandardOutput = $true
        $pinfo.RedirectStandardError = $true
        $pinfo.UseShellExecute = $false
        $pinfo.CreateNoWindow = $true

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $pinfo
        $process.Start() | Out-Null
        
        # 4. SHIELD DE CPU: Throttle da prioridade do GBAK
        try {
            # Baixa prioridade de CPU para nao competir com Firebird (mas sem limitar nucleos para ser rapido)
            $process.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal
        } catch {}
        
        # Timeout de 2 horas (7200000 ms)
        if ($process.WaitForExit(7200000)) {
            if ($process.ExitCode -eq 0 -and (Test-Path $tempFbk)) {
                $gbakSuccess = $true
                $global:gbakTimer.Stop()
                $fbkSizeMB = [math]::Round(((Get-Item $tempFbk).Length / 1MB), 2)
                $gbakElapsedStr = Format-DurationText $global:gbakTimer.Elapsed
                Log-Message "gbak.exe concluido com sucesso! Arquivo FBK gerado ($fbkSizeMB MB) em $gbakElapsedStr."
                break
            } else {
                $gbakError = "Sem detalhes no log."
                if (Test-Path $gbakLog) { $gbakError = Get-Content $gbakLog -Tail 5 | Out-String }
                Log-Message "Tentativa $attempt falhou. Codigo: $($process.ExitCode). Erro: $gbakError"
            }
        } else {
            $process.Kill()
            $gbakError = "gbak excedeu o limite de 2 horas e foi finalizado."
            Log-Message "Tentativa $attempt falhou: $gbakError"
        }
    } catch {
        $gbakError = "$_"
        Log-Message "Excecao ao rodar gbak na tentativa ${attempt}: $_"
    }

    if ($attempt -lt $retryCount) {
        Log-Message "Aguardando $retryInterval segundos antes de retentar..."
        Start-Sleep -Seconds $retryInterval
    }
}

if (-not $gbakSuccess) {
    $errMsg = "ERRO CRITICO: Falha no gbak em todas as $retryCount tentativas. Backup abortado. Detalhes: $gbakError"
    Log-Message $errMsg
    Send-BackupNotification -Status "FALHA" -SubjectInfo "Falha no GBAK ($TaskName)" -BodyDetails $errMsg -DbPath $dbPath -DbSize "$dbSizeMB"
    if (Test-Path $lockFile) { Remove-Item $lockFile -Force -ErrorAction SilentlyContinue }

    # Se a tarefa for externa, avaliar e alertar se a contingencia externa esta atrasada
    $isExternalTask = ($TaskName -match "EXTERN" -or $TaskName -eq "BKP_EXTERNO")
    if ($isExternalTask) {
        Test-ExternalDestinationsHealth -TaskName $TaskName -Destinations $destList -FailureReason "Falha no gbak.exe (Erro no banco de dados Firebird)"
    }
    exit 1
}

# --- FASE 4: COMPACTACAO DIRETA FBK -> ZIP (PRIORIDADE BAIXA) ---
$global:zipTimer.Restart()

# Impressao digital do .fbk ANTES de compactar. E contra ela que o ZIP sera conferido,
# e por isso o .fbk so pode ser apagado depois que a conferencia passar.
$fbkEntryName = Split-Path $tempFbk -Leaf
$fbkSizeBytes = (Get-Item $tempFbk).Length
Log-Message "Calculando impressao digital SHA-256 do backup de origem..."
$fbkSha = Get-Sha256OfFile -Path $tempFbk
if ([string]::IsNullOrWhiteSpace($fbkSha)) {
    $errMsg = "ERRO CRITICO: nao foi possivel calcular o SHA-256 do arquivo .fbk gerado ($tempFbk). Backup abortado para nao distribuir arquivo nao verificavel."
    Log-Message $errMsg
    Send-BackupNotification -Status "FALHA" -SubjectInfo "Falha na Verificacao de Integridade ($TaskName)" -BodyDetails $errMsg -DbPath $dbPath -DbSize "$dbSizeMB"
    if (Test-Path $tempFbk) { Remove-Item $tempFbk -Force -ErrorAction SilentlyContinue }
    if (Test-Path $lockFile) { Remove-Item $lockFile -Force -ErrorAction SilentlyContinue }
    exit 1
}
Log-Message "Origem: $fbkEntryName | $([math]::Round($fbkSizeBytes/1MB,2)) MB | SHA-256 $($fbkSha.Substring(0,16))..."

Log-Message "Compactando backup para arquivo .ZIP (Compressao Maxima em Prioridade Baixa)..."
$zipSizeMB = 0
$zipSha = $null
try {
    if (Test-Path $tempZip) { Remove-Item $tempZip -Force -ErrorAction SilentlyContinue }
    
    $compressionSuccess = $false
    try {
        Compress-Archive -Path $tempFbk -DestinationPath $tempZip -CompressionLevel Optimal -Force -ErrorAction Stop
        $compressionSuccess = $true
    } catch {
        Log-Message "Aviso: Compress-Archive nativo falhou. Usando fallback .NET ZipFile..."
        if (Test-Path $tempZip) { Remove-Item $tempZip -Force -ErrorAction SilentlyContinue }
        try {
            Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
            Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
        } catch {
            [System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression") | Out-Null
            [System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null
        }
        
        $zip = [System.IO.Compression.ZipFile]::Open($tempZip, [System.IO.Compression.ZipArchiveMode]::Create)
        $entryName = Split-Path $tempFbk -Leaf
        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $tempFbk, $entryName, [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
        $zip.Dispose()
        $compressionSuccess = $true
    }

    if ($compressionSuccess -and (Test-Path $tempZip) -and ((Get-Item $tempZip).Length -gt 0)) {
        $zipSizeMB = [math]::Round(((Get-Item $tempZip).Length / 1MB), 2)

        # PORTAO DE INTEGRIDADE: le o ZIP de volta e confere o conteudo contra o .fbk.
        # So passando daqui o .fbk original pode ser descartado.
        Log-Message "Verificando integridade do ZIP gerado (releitura + SHA-256)..."
        $verif = Test-BackupZipIntegrity -ZipPath $tempZip -ExpectedEntryName $fbkEntryName -ExpectedSize $fbkSizeBytes -ExpectedSha256 $fbkSha
        if (-not $verif.Ok) {
            throw "ZIP GERADO ESTA CORROMPIDO. $($verif.Reason)"
        }
        Log-Message "Integridade do ZIP CONFIRMADA: $($verif.Reason)"

        # Impressao digital do proprio ZIP, usada para conferir cada copia nos destinos
        $zipSha = Get-Sha256OfFile -Path $tempZip
        if ([string]::IsNullOrWhiteSpace($zipSha)) { throw "Nao foi possivel calcular o SHA-256 do ZIP verificado." }

        $global:zipTimer.Stop()
        $zipElapsedStr = Format-DurationText $global:zipTimer.Elapsed
        Log-Message "Arquivo ZIP gerado e verificado: $tempZip ($zipSizeMB MB) em $zipElapsedStr | SHA-256 $($zipSha.Substring(0,16))..."

        # Agora sim e seguro remover o FBK bruto para poupar espaco em disco
        Remove-Item $tempFbk -Force -ErrorAction SilentlyContinue
    } else {
        throw "Arquivo ZIP nao foi gerado corretamente ou esta vazio."
    }
} catch {
    $errMsg = "ERRO na compactacao do ZIP: $_"
    Log-Message $errMsg
    Send-BackupNotification -Status "FALHA" -SubjectInfo "Falha na Compactacao ($TaskName)" -BodyDetails $errMsg -DbPath $dbPath -DbSize "$dbSizeMB"
    if (Test-Path $tempFbk) { Remove-Item $tempFbk -Force -ErrorAction SilentlyContinue }
    if (Test-Path $lockFile) { Remove-Item $lockFile -Force -ErrorAction SilentlyContinue }
    exit 1
}

# --- FASE 5: DISTRIBUICAO PARA DESTINOS E EXPURGO AUTOMATICO ---
$fileName = Split-Path $tempZip -Leaf
$localSuccessList = @()
$networkSuccessList = @()
$failedDestinations = @()

foreach ($destTrimmed in $resolvedDestList) {
    $isNetwork = $destTrimmed.StartsWith("\\")
    $destTypeTag = if ($isNetwork) { "[REDE UNC]" } else { "[LOCAL]" }
    Log-Message "Gravando backup ZIP no destino $($destTypeTag) - $destTrimmed"
    
    $destSuccess = $false
    for ($attempt = 1; $attempt -le $retryCount; $attempt++) {
        try {
            # Se for caminho de rede UNC (\\servidor\compartilhamento ou \\servidor\c$\...)
            if ($isNetwork) {
                if (-not [string]::IsNullOrWhiteSpace($networkUser)) {
                    $cleanPath = $destTrimmed.TrimStart('\')
                    $parts = $cleanPath.Split('\')
                    $uncHost = if ($parts.Length -ge 1) { $parts[0] } else { "" }
                    $uncRoot = if ($parts.Length -ge 2) { "\\$($parts[0])\$($parts[1])" } else { $destTrimmed }
                    
                    # Normaliza usuario (remove barras extras e troca / por \)
                    $normUser = $networkUser.Replace('/', '\')
                    while ($normUser.Contains('\\')) { $normUser = $normUser.Replace('\\', '\') }

                    Log-Message "Autenticando rede em $uncRoot com usuario '$normUser'..."
                    try {
                        & net.exe use $uncRoot /delete /yes 2>&1 | Out-Null
                        $netUseArgs = @("use", "`"$uncRoot`"", "`"$networkPassword`"", "/user:`"$normUser`"", "/persistent:no")
                        $netUseProc = Start-Process -FilePath "net.exe" -ArgumentList $netUseArgs -NoNewWindow -Wait -PassThru
                        if ($netUseProc.ExitCode -ne 0 -and $normUser -notmatch '\\' -and -not [string]::IsNullOrWhiteSpace($uncHost)) {
                            $hostUser = "$uncHost\$normUser"
                            Log-Message "Tentando autenticacao com prefixo do computador: $hostUser..."
                            $netUseArgs = @("use", "`"$uncRoot`"", "`"$networkPassword`"", "/user:`"$hostUser`"", "/persistent:no")
                            $netUseProc = Start-Process -FilePath "net.exe" -ArgumentList $netUseArgs -NoNewWindow -Wait -PassThru
                        }
                        if ($netUseProc.ExitCode -ne 0) {
                            Log-Message "Aviso: net use retornou codigo $($netUseProc.ExitCode) para $uncRoot."
                        } else {
                            Log-Message "Autenticacao de rede em $uncRoot estabelecida com sucesso."
                        }
                    } catch {
                        Log-Message "Aviso ao tentar autenticar rede: $_"
                    }
                }
            }

            # Cria a pasta caso nao exista
            if (-not (Test-Path $destTrimmed)) {
                New-Item -ItemType Directory -Path $destTrimmed -Force -ErrorAction Stop | Out-Null
            }

            $finalPath = Join-Path $destTrimmed $fileName

            # Copia o arquivo .ZIP para o destino
            Copy-Item -Path $tempZip -Destination $finalPath -Force -ErrorAction Stop

            if (-not (Test-Path $finalPath)) { throw "Arquivo de destino nao foi gravado." }

            # CONFERENCIA DA COPIA: tamanho e SHA-256 contra o ZIP de origem ja verificado.
            # Uma copia truncada ou com bits trocados (queda de rede, disco com defeito)
            # tem tamanho > 0 e passaria na checagem antiga; aqui ela e reprovada e a
            # tentativa e refeita, sem nunca chegar na politica de retencao.
            $destLen = (Get-Item $finalPath).Length
            $srcLen  = (Get-Item $tempZip).Length
            if ($destLen -ne $srcLen) {
                throw "Copia incompleta em '$finalPath': $destLen bytes gravados de $srcLen esperados."
            }

            Log-Message "Conferindo integridade da copia gravada em $destTrimmed ..."
            $destSha = Get-Sha256OfFile -Path $finalPath
            if ([string]::IsNullOrWhiteSpace($destSha)) {
                throw "Nao foi possivel ler de volta a copia em '$finalPath' para conferencia."
            }
            if ($destSha -ne $zipSha) {
                throw "COPIA CORROMPIDA em '$finalPath': SHA-256 nao confere com a origem (arquivo chegou alterado)."
            }

            if ($true) {
                $destSuccess = $true
                if ($isNetwork) {
                    $networkSuccessList += $finalPath
                } else {
                    $localSuccessList += $finalPath
                }
                Log-Message "Backup ZIP gravado e CONFERIDO em: $finalPath (SHA-256 identico a origem)"

                # Politica de Retencao (Expurgo dos mais antigos por tarefa / prefixo)
                try {
                    Log-Message "Aplicando politica de retencao em $destTrimmed (Manter ultimos $keepBackupsCount backups do prefixo '$basePrefix')..."
                    $escapedPrefix = [regex]::Escape($basePrefix)
                    $backupFiles = Get-ChildItem -Path $destTrimmed -File -ErrorAction SilentlyContinue | Where-Object {
                        $_.Name -match "^${escapedPrefix}[-_]\d{4,}\.zip$" -or $_.Name -match "^${escapedPrefix}[-_]\d{8}_\d{6}\.zip$"
                    } | Sort-Object LastWriteTime -Descending
                    
                    if ($backupFiles.Count -gt $keepBackupsCount) {
                        $filesToRemove = $backupFiles | Select-Object -Skip $keepBackupsCount
                        foreach ($oldFile in $filesToRemove) {
                            Log-Message "Excluindo backup excedente antigo: $($oldFile.Name)"
                            Remove-Item $oldFile.FullName -Force -ErrorAction SilentlyContinue
                        }
                    }
                } catch {
                    Log-Message "Aviso na politica de retencao em $($destTrimmed): $_"
                }

                break
            } else {
                throw "Arquivo de destino nao foi gravado ou esta vazio."
            }
        } catch {
            Log-Message "Tentativa $attempt de copia para '$destTrimmed' falhou: $_"
            # Nao deixar arquivo reprovado na pasta: ele seria contado como "backup
            # existente" pelo monitor e pela numeracao sequencial, mascarando a falha.
            try {
                if (-not [string]::IsNullOrWhiteSpace($finalPath) -and (Test-Path $finalPath)) {
                    Remove-Item $finalPath -Force -ErrorAction SilentlyContinue
                    Log-Message "Copia reprovada removida do destino para nao mascarar a falha: $finalPath"
                }
            } catch {}
        }

        if ($attempt -lt $retryCount) {
            Start-Sleep -Seconds $retryInterval
        }
    }

    if (-not $destSuccess) {
        $failedDestinations += $destTrimmed
        if ($isNetwork) {
            Log-Message "AVISO DE REDE: O computador remoto '$destTrimmed' esta inacessivel (equipamento offline, desligado ou sem permissao). O backup local permanece 100% seguro."
        } else {
            Log-Message "ERRO: Falha definitiva de copia para o destino local: $destTrimmed"
        }
    }
}

# GARANTIA DE FAIL-SAFE LOCAL: Se nenhum destino local foi gravado e todos os destinos externos/rede falharam
if ($localSuccessList.Count -eq 0 -and $networkSuccessList.Count -eq 0) {
    $localSafeDir = if (Test-Path "D:\") { "D:\BKP_SISMOTEL" } else { "C:\BKP_SISMOTEL" }
    Log-Message "ESCUDO FAIL-SAFE ATIVADO: Todos os destinos configurados falharam ou estao indisponiveis. Gravando copia de seguranca garantida de ultima linha no servidor local em: $localSafeDir"
    try {
        if (-not (Test-Path $localSafeDir)) { New-Item -ItemType Directory -Path $localSafeDir -Force -ErrorAction Stop | Out-Null }
        $safeFinalPath = Join-Path $localSafeDir $fileName
        Copy-Item -Path $tempZip -Destination $safeFinalPath -Force -ErrorAction Stop
        if (Test-Path $safeFinalPath) {
            # A copia de ultima linha tambem passa pela conferencia: e justamente a que
            # sera usada num desastre, entao nao pode ser aceita sem verificacao.
            $safeSha = Get-Sha256OfFile -Path $safeFinalPath
            if ($safeSha -eq $zipSha) {
                $localSuccessList += $safeFinalPath
                Log-Message "Copia de seguranca local gravada e CONFERIDA em: $safeFinalPath"
            } else {
                Log-Message "ERRO: a copia fail-safe em '$safeFinalPath' nao confere com a origem (SHA-256 divergente). Arquivo descartado."
                Remove-Item $safeFinalPath -Force -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Log-Message "Aviso no escudo fail-safe local: $_"
    }
}

# --- FASE 6: LIMPEZA FINAL DE ARQUIVOS TEMPORARIOS E LIBERACAO DO LOCK ---
if (Test-Path $tempZip) { Remove-Item $tempZip -Force -ErrorAction SilentlyContinue }
if (Test-Path $gbakLog) { Remove-Item $gbakLog -Force -ErrorAction SilentlyContinue }
if (Test-Path $lockFile) { Remove-Item $lockFile -Force -ErrorAction SilentlyContinue }

if ($global:routineTimer.IsRunning) { $global:routineTimer.Stop() }
$durationStr = Format-DurationText $global:routineTimer.Elapsed
$gbakDurationStr = if ($global:gbakTimer.ElapsedMilliseconds -gt 0) { Format-DurationText $global:gbakTimer.Elapsed } else { "N/A" }
$zipDurationStr = if ($global:zipTimer.ElapsedMilliseconds -gt 0) { Format-DurationText $global:zipTimer.Elapsed } else { "N/A" }

$compRatio = ""
if ($dbSizeMB -gt 0 -and $zipSizeMB -gt 0) {
    $pct = [Math]::Round((1.0 - ([double]$zipSizeMB / [double]$dbSizeMB)) * 100, 1)
    if ($pct -gt 0) {
        $compRatio = "$pct% menor"
    }
}

$diskInfo = ""
try {
    $driveLetter = [System.IO.Path]::GetPathRoot($dbPath)
    if (-not [string]::IsNullOrWhiteSpace($driveLetter)) {
        $dInfo = New-Object System.IO.DriveInfo($driveLetter)
        if ($dInfo.IsReady) {
            $freeGB = [Math]::Round($dInfo.AvailableFreeSpace / 1GB, 1)
            $totalGB = [Math]::Round($dInfo.TotalSize / 1GB, 1)
            $diskInfo = "$driveLetter ($freeGB GB livres de $totalGB GB)"
        }
    }
} catch {}

# Verificacao de integridade final: ao menos 1 destino deve ter sido gravado com sucesso
if ($localSuccessList.Count -eq 0 -and $networkSuccessList.Count -eq 0) {
    $errMsg = "ERRO CRITICO: Nenhum destino (local ou rede) pode ser gravado com sucesso! Backup abortado."
    Log-Message $errMsg
    Send-BackupNotification -Status "FALHA" -SubjectInfo "Falha Geral de Destinos ($TaskName)" -BodyDetails $errMsg -ZipFile $fileName -ZipSize "$zipSizeMB" -FbkSize "$fbkSizeMB" -DbPath $dbPath -DbSize "$dbSizeMB" -DurationStr $durationStr -GbakDurationStr $gbakDurationStr -ZipDurationStr $zipDurationStr -CompressionRatio $compRatio -FreeSpaceInfo $diskInfo
    exit 1
}

$allSuccessList = $localSuccessList + $networkSuccessList
Log-Message "Rotina de backup concluida com SUCESSO! ($($allSuccessList.Count) destino(s) gravado(s))."

# Carimba a conclusao para a guarda anti-duplicidade da proxima invocacao.
# Gravado apenas em caso de sucesso: se a rotina falhar, um novo disparo deve poder tentar.
try {
    $runs = @{}
    if (Test-Path $lastRunFile) {
        $prevRuns = Get-Content $lastRunFile -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($null -ne $prevRuns) {
            foreach ($prop in $prevRuns.psobject.Properties) { $runs[$prop.Name] = $prop.Value }
        }
    }
    $runs[$TaskName] = (Get-Date).ToString("o")
    $runs | ConvertTo-Json | Set-Content $lastRunFile -Encoding UTF8
} catch {
    Log-Message "Aviso ao registrar a conclusao da tarefa: $_"
}

$bodyReport = @"
Relatorio de Execucao da Rotina:
Status: SUCESSO $(if ($failedDestinations.Count -gt 0) { '(COM AVISO DE REDE)' } else { 'COMPLETO' })
Tarefa: $TaskName
Computador / Servidor: $env:COMPUTERNAME
Arquivo Gerado: $fileName
Tamanho Compactado: $zipSizeMB MB
Banco Original: $dbPath ($dbSizeMB MB)

Destinos Gravados com Sucesso:
$($allSuccessList -join "`r`n")
"@

# Rastreamento e Monitoramento Continuo de Destinos Externos (Watchdog 24h)
$networkTrackerFile = Join-Path $scriptDir "network_tracker.json"
$netTracker = @{}
if (Test-Path $networkTrackerFile) {
    try { $netTracker = ConvertTo-HashtableCompat (Get-Content $networkTrackerFile -Raw -Encoding UTF8 | ConvertFrom-Json) }
    catch { Log-Message "Aviso: falha ao ler o rastreador de destinos: $_" }
}

# 1. Processa Sucessos (Renova o contador no arquivo real)
foreach ($successPath in ($networkSuccessList + $localSuccessList)) {
    $destDir = Split-Path $successPath -Parent
    if (-not $netTracker.ContainsKey($destDir)) { $netTracker[$destDir] = @{} }
    $netTracker[$destDir].LastSuccess = (Get-Date).ToString("o")
    $netTracker[$destDir].FirstFailure = $null
    $netTracker[$destDir].LastAlert = $null
}
try { $netTracker | ConvertTo-Json -Depth 10 | Set-Content $networkTrackerFile -Encoding UTF8 } catch {}

# 2. Executa a Verificacao Blindada de Saude de Destinos Externos / Rede (24 Horas)
$isExternalTask = ($TaskName -match "EXTERN" -or $TaskName -eq "BKP_EXTERNO")
if ($failedDestinations.Count -gt 0 -or $isExternalTask) {
    $destsToCheck = if ($failedDestinations.Count -gt 0) { $failedDestinations } else { $allDestinations }
    Test-ExternalDestinationsHealth -TaskName $TaskName -Destinations $destsToCheck
}

if ($failedDestinations.Count -gt 0) {
    $bodyReport += @"

Avisos de Destinos Nao Sincronizados (Rede):
$($failedDestinations -join "`r`n")
(Observacao: O backup local no servidor foi concluido com 100% de integridade. Verifique se os computadores da rede acima estao ligados.)
"@
    Send-BackupNotification -Status "SUCESSO" -SubjectInfo "Backup $TaskName Concluido ($zipSizeMB MB) [Alerta Rede]" -BodyDetails $bodyReport -ZipFile $fileName -ZipSize "$zipSizeMB" -FbkSize "$fbkSizeMB" -DbPath $dbPath -DbSize "$dbSizeMB" -DurationStr $durationStr -GbakDurationStr $gbakDurationStr -ZipDurationStr $zipDurationStr -CompressionRatio $compRatio -FreeSpaceInfo $diskInfo -SuccessDests $allSuccessList -WarningDests $failedDestinations
} else {
    Send-BackupNotification -Status "SUCESSO" -SubjectInfo "Backup $TaskName Concluido com Sucesso ($zipSizeMB MB)" -BodyDetails $bodyReport -ZipFile $fileName -ZipSize "$zipSizeMB" -FbkSize "$fbkSizeMB" -DbPath $dbPath -DbSize "$dbSizeMB" -DurationStr $durationStr -GbakDurationStr $gbakDurationStr -ZipDurationStr $zipDurationStr -CompressionRatio $compRatio -FreeSpaceInfo $diskInfo -SuccessDests $allSuccessList -WarningDests @()
}

# --- FASE 7: AUDITORIA PREVENTIVA DIARIA DE INTEGRIDADE (SANDBOX ISOLADA) ---
try {
    if ($null -eq $global:configData -or $null -eq $global:configData.Preferences) {
        if (Test-Path $configFile) {
            try { $global:configData = Get-Content $configFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch {}
        }
    }
    if ($null -ne $global:configData -and $null -ne $global:configData.Preferences) {
        $p = $global:configData.Preferences
        $enableAudit = if ($null -ne $p.EnableDailyAudit) { [bool]$p.EnableDailyAudit } else { $true }
        $auditHour = if ($null -ne $p.DailyAuditHour) { [int]$p.DailyAuditHour } else { 3 }
        $currentHour = (Get-Date).Hour
        $todayStr = Get-Date -Format "yyyy-MM-dd"
        
        if ($enableAudit -and ($currentHour -eq $auditHour) -and ($p.LastAuditDate -ne $todayStr)) {
            Log-Message "Horario agendado da Auditoria Diaria alcancado ($auditHour:30h). Iniciando auditoria preventiva em sandbox..."
            Invoke-DatabaseHealthAudit -TaskName $TaskName
        }
    }
} catch {
    Log-Message "Aviso na chamada da auditoria diaria: $_"
}

# 11. CAMADA AUTO-UPDATE EM NUVEM (MEC LiveUpdate via GitHub)
try {
    Invoke-MecLiveUpdate
} catch {
    Log-Message "Aviso na verificacao de auto-update: $_"
}

Log-Message "======================================================"
exit 0
