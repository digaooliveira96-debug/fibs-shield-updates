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
    [switch]$Manual,
    [switch]$ScheduledAudit,
    [switch]$TestNetworkAccess
)

# Versao UNICA do motor. O LiveUpdate compara com o manifesto remoto e os testes
# garantem que ela e igual a version.json, AssemblyInfo.cs e ao AppVersion do .iss.
# (Versao divergente fazia o LiveUpdate reinstalar o pacote a cada 2 horas.)
$script:EngineVersion = "2.2.34"
# Compatibilidade com clientes antigos no LiveUpdate: Invoke-TaskBackup

try { Add-Type -AssemblyName System.Security -ErrorAction Stop } catch {}

function Test-IsDpapiBlob {
    param([string]$Value)
    return (-not [string]::IsNullOrWhiteSpace($Value) -and $Value.StartsWith("AQAAANCMnd8BF"))
}

# Devolve o texto decifrado, o proprio valor se ele nao estiver cifrado, ou $null
# quando o blob DPAPI NAO abre nesta maquina (config copiado de outro servidor,
# reinstalacao do Windows). Antes o blob cifrado era devolvido como se fosse a
# senha, e o erro aparecia como "senha recusada" -- mascarando a causa real.
function Unprotect-String {
    param([string]$cipherText)
    if ([string]::IsNullOrWhiteSpace($cipherText)) { return $cipherText }
    if (-not (Test-IsDpapiBlob $cipherText)) { return $cipherText }
    try {
        $bytes = [Convert]::FromBase64String($cipherText)
        $decBytes = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
        return [System.Text.Encoding]::UTF8.GetString($decBytes)
    } catch { return $null }
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
    } catch {
        Log-Message "AVISO DE SEGURANCA: nao foi possivel cifrar uma credencial com DPAPI ($($_.Exception.Message)). Ela permanece como estava."
        return $plainText
    }
}

# ==============================================================================
# EXCLUSAO MUTUA E GRAVACAO SEGURA DE ARQUIVOS
# ==============================================================================
# Mutex nomeado do Windows: o sistema operacional libera a trava sozinho quando o
# processo morre (queda de energia, kill, excecao). O antigo lock por arquivo+PID
# ficava orfao apos um reboot e, se o PID fosse reaproveitado por outro processo,
# bloqueava TODOS os backups em silencio.
$script:MutexPrefix = "Global\MEC_Shield_"

function New-MecNamedMutex {
    param([string]$Name)
    $fullName = $script:MutexPrefix + $Name
    $created = $false
    try {
        # SYSTEM, Administradores, usuario atual e usuarios autenticados:
        # garante interoperabilidade entre servico SYSTEM e painel do operador
        $sec = New-Object System.Security.AccessControl.MutexSecurity
        $sids = @("S-1-5-18", "S-1-5-32-544", "S-1-5-11")
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        if ($currentUser -and -not ($sids -contains $currentUser.Value)) { $sids += $currentUser.Value }
        foreach ($sid in $sids) {
            try {
                $id = New-Object System.Security.Principal.SecurityIdentifier($sid)
                $rule = New-Object System.Security.AccessControl.MutexAccessRule($id, [System.Security.AccessControl.MutexRights]::FullControl, [System.Security.AccessControl.AccessControlType]::Allow)
                $sec.AddAccessRule($rule)
            } catch {}
        }
        return New-Object System.Threading.Mutex($false, $fullName, [ref]$created, $sec)
    } catch {
        try {
            return [System.Threading.Mutex]::OpenExisting($fullName)
        } catch {
            return New-Object System.Threading.Mutex($false, $fullName, [ref]$created)
        }
    }
}

# Tenta obter o mutex. Devolve $true se obteve (inclusive quando o dono anterior
# morreu sem liberar -- AbandonedMutexException significa "agora e seu").
function Enter-MecMutex {
    param([System.Threading.Mutex]$Mutex, [int]$TimeoutMs = 0)
    try { return $Mutex.WaitOne($TimeoutMs) }
    catch [System.Threading.AbandonedMutexException] { return $true }
}

function Exit-MecMutex {
    param([System.Threading.Mutex]$Mutex)
    if ($null -eq $Mutex) { return }
    try { $Mutex.ReleaseMutex() } catch {}
}

# Executa um bloco com o mutex de estado (config.json e arquivos *.json de estado
# compartilhados entre motor, monitor e interface).
function Invoke-WithMecLock {
    param([string]$Name, [scriptblock]$Script, [int]$TimeoutMs = 30000)
    $m = $null
    $got = $false
    try {
        $m = New-MecNamedMutex -Name $Name
        $got = Enter-MecMutex -Mutex $m -TimeoutMs $TimeoutMs
        if (-not $got) { Log-Message "Aviso: trava '$Name' ocupada ha mais de $([int]($TimeoutMs/1000))s; prosseguindo sem ela." }
        & $Script
    } finally {
        if ($got) { Exit-MecMutex $m }
        if ($null -ne $m) { try { $m.Dispose() } catch {} }
    }
}

# Grava texto de forma atomica: escreve num temporario na MESMA pasta e troca com
# File.Replace/Move. Uma queda de energia no meio deixa o arquivo antigo intacto,
# nunca um JSON truncado (que fazia o servico enxergar 0 tarefas e parar em silencio).
function Write-TextFileAtomic {
    param([string]$Path, [string]$Content, [string]$BackupPath = $null)
    $dir = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $tmp = "$Path.$PID.tmp"
    [System.IO.File]::WriteAllText($tmp, $Content, (New-Object System.Text.UTF8Encoding($true)))
    # Outro processo lendo o arquivo naquele instante (antivirus, interface) pode
    # impedir a troca: tenta algumas vezes antes de desistir.
    for ($i = 1; $i -le 5; $i++) {
        try {
            if (Test-Path $Path) {
                if ([string]::IsNullOrWhiteSpace($BackupPath)) {
                    # [NullString]::Value: $null viraria "" ao chamar o .NET e o Replace falharia
                    [System.IO.File]::Replace($tmp, $Path, [NullString]::Value)
                } else {
                    [System.IO.File]::Replace($tmp, $Path, $BackupPath)
                }
            } else {
                [System.IO.File]::Move($tmp, $Path)
            }
            return
        } catch {
            if ($i -eq 5) {
                Remove-Item $tmp -Force -ErrorAction SilentlyContinue
                throw
            }
            Start-Sleep -Milliseconds (200 * $i)
        }
    }
}

function Save-JsonState {
    param([string]$Path, $Data, [int]$Depth = 10)
    $json = $Data | ConvertTo-Json -Depth $Depth
    Write-TextFileAtomic -Path $Path -Content $json
}

# Le e interpreta o config.json. Se o arquivo estiver ilegivel (truncado), usa a
# ultima copia boa (config.json.bak) gerada pela gravacao atomica.
function Read-ConfigData {
    param([string]$Path = $configFile)
    foreach ($candidate in @($Path, "$Path.bak")) {
        if (-not (Test-Path $candidate)) { continue }
        for ($i = 1; $i -le 3; $i++) {
            try {
                $raw = [System.IO.File]::ReadAllText($candidate, [System.Text.Encoding]::UTF8)
                $obj = $raw | ConvertFrom-Json
                if ($null -ne $obj -and $null -ne $obj.Tasks) {
                    if ($candidate -ne $Path) {
                        Log-Message "ATENCAO: config.json ilegivel. Usando a ultima copia valida: $candidate"
                    }
                    return $obj
                }
                break
            } catch {
                Start-Sleep -Milliseconds 300
            }
        }
    }
    return $null
}

function Save-ConfigData {
    param($Config)
    $json = $Config | ConvertTo-Json -Depth 10
    Invoke-WithMecLock -Name "Config" -Script {
        Write-TextFileAtomic -Path $configFile -Content $json -BackupPath "$configFile.bak"
    }
}

function ConvertTo-HtmlSafe {
    param([string]$Text)
    if ($null -eq $Text) { return "" }
    return [System.Net.WebUtility]::HtmlEncode($Text)
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
        # Leitura, conversao e gravacao sob a trava de configuracao: a interface
        # (ConfigTypes.Save) usa a mesma trava, entao uma nao apaga a gravacao da outra.
        Invoke-WithMecLock -Name "Config" -Script {
            $cfg = Read-ConfigData
            if ($null -eq $cfg) { return }
            $mudou = $false
            $campos = @()

            if ($null -ne $cfg.Preferences -and -not [string]::IsNullOrWhiteSpace($cfg.Preferences.SmtpPass) `
                -and -not (Test-IsDpapiBlob $cfg.Preferences.SmtpPass)) {
                $cfg.Preferences.SmtpPass = Protect-String $cfg.Preferences.SmtpPass
                $mudou = $true; $campos += "SmtpPass"
            }
            foreach ($t in $cfg.Tasks) {
                if ($null -eq $t.NetworkPassword) {
                    # Add-Member cobre tambem tarefas antigas sem a propriedade
                    $t | Add-Member -NotePropertyName NetworkPassword -NotePropertyValue "" -Force
                    $mudou = $true; $campos += "$($t.TaskName).NetworkPassword (null para vazio)"
                }
                foreach ($nome in @("DbPassword", "NetworkPassword")) {
                    $valor = $t.$nome
                    if (-not [string]::IsNullOrWhiteSpace($valor) -and -not (Test-IsDpapiBlob $valor)) {
                        $t.$nome = Protect-String $valor
                        $mudou = $true; $campos += "$($t.TaskName).$nome"
                    }
                }
            }

            if ($mudou) {
                $json = $cfg | ConvertTo-Json -Depth 10
                Write-TextFileAtomic -Path $configFile -Content $json -BackupPath "$configFile.bak"
                Log-Message "SEGURANCA: credencial(is) normalizada(s) ou convertida(s) neste servidor ($($campos -join ', ')). O config.json local nao guarda senha legivel."
            }
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
# Modos auxiliares (monitor, auditoria, atualizacao) tem log proprio. Antes eles
# escreviam no log da tarefa BKP_SISMOTEL, e o servico/startup guard confundiam essa
# escrita com "backup recente", pulando o backup de boot apos queda de energia.
$logName = if ($CheckExternalHealth) { "monitor_backup_log.txt" }
           elseif ($RunAuditOnly)    { "auditoria_log.txt" }
           elseif ($CheckUpdateOnly) { "liveupdate_log.txt" }
           elseif ($TestNetworkAccess) { "teste_rede_log.txt" }
           else                      { "backup_$($TaskName)_log.txt" }
$logFile = Join-Path $logDir $logName

# Funcao de Registro em Log com Rotacao Ativa (Limite 5 MB para evitar crescimento infinito)
# Usa Write-Host (e nao Write-Output): assim uma linha de log dentro de uma funcao
# nunca se mistura ao valor de retorno dela. O console redirecionado (AuditDialog)
# continua recebendo as linhas normalmente.
function Log-Message {
    param ([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logLine = "[$timestamp] [$TaskName] $Message"
    Write-Host $logLine
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

        # Unidade que existe NESTA sessao (disco fisico, particao, USB) e usada como
        # esta. Antes, uma letra local podia ser trocada pelo mapeamento de rede de
        # outro usuario que tivesse a mesma letra.
        $isLocalDisk = $false
        try {
            if (Test-Path "${driveLetter}:\") {
                $wmiLocal = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='${driveLetter}:'" -ErrorAction SilentlyContinue
                if ($null -eq $wmiLocal -or $wmiLocal.DriveType -ne 4) { $isLocalDisk = $true }
            }
        } catch {}
        if ($isLocalDisk) { return $p }

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

        if ([string]::IsNullOrWhiteSpace($remotePath)) {
            try {
                $netLines = net.exe use 2>$null
                foreach ($line in $netLines) {
                    if ($line -match "(?i)\b${driveLetter}:\s+(\\\\[^\s]+)") {
                        $remotePath = $matches[1]
                        break
                    }
                }
            } catch {}
        }

        # O mapeamento so e visivel sob SYSTEM enquanto o usuario dono esta logado
        # (hive carregado). Guardamos a ultima traducao conhecida para que a rotina
        # da madrugada, sem ninguem logado, use o mesmo caminho UNC.
        $cacheFile = Join-Path $scriptDir "mapped_drives_cache.json"
        if (-not [string]::IsNullOrWhiteSpace($remotePath)) {
            try {
                Invoke-WithMecLock -Name "State" -Script {
                    $cache = @{}
                    if (Test-Path $cacheFile) {
                        $cache = ConvertTo-HashtableCompat (Get-Content $cacheFile -Raw -Encoding UTF8 | ConvertFrom-Json)
                    }
                    if ($cache[$driveLetter] -ne $remotePath) {
                        $cache[$driveLetter] = $remotePath
                        Save-JsonState -Path $cacheFile -Data $cache
                    }
                }
            } catch {}
        } else {
            try {
                if (Test-Path $cacheFile) {
                    $cache = ConvertTo-HashtableCompat (Get-Content $cacheFile -Raw -Encoding UTF8 | ConvertFrom-Json)
                    if (-not [string]::IsNullOrWhiteSpace($cache[$driveLetter])) {
                        $remotePath = $cache[$driveLetter]
                        Log-Message "Unidade ${driveLetter}: nao visivel para esta conta; usando a ultima traducao conhecida: $remotePath"
                    }
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

# Identifica se uma unidade ou caminho pertence a uma particao reservada do sistema
# (ex: 'Reservado pelo Sistema', EFI, WinRE ou capacidade menor que 4 GB) para que
# nunca seja selecionada ou usada como destino de backup.
# Particao do sistema pelo ROTULO EXATO ou pelo tamanho (< 1 GB). Antes o rotulo era
# comparado por trecho (*esp*, *efi*, *boot*, *recupera*...) e discos de dados como
# "ESPELHO", "DESPESAS" ou "BKP_RECUPERACAO" eram descartados sem nenhum alerta.
function Test-IsReservedVolume {
    param([string]$Label, [double]$TotalBytes)
    if ($TotalBytes -gt 0 -and $TotalBytes -lt 1GB) { return $true }
    $l = "$Label".Trim().ToLowerInvariant()
    return ($l -match '^(system reserved|reservado pelo sistema|sistema reservado|recovery|recupera.{1,3}o|efi|esp|boot|winre|windows re tools|hp_recovery|lenovo_recovery)$')
}

function Test-IsSystemReservedDrive {
    param ([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.StartsWith("\\")) { return $false }
    try {
        $root = [System.IO.Path]::GetPathRoot($Path)
        if ([string]::IsNullOrWhiteSpace($root)) { return $false }
        $driveLetter = $root.TrimEnd('\', '/')
        if (-not (Test-Path "${driveLetter}\")) { return $false }
        $di = New-Object System.IO.DriveInfo($driveLetter)
        if (-not $di.IsReady) { return $false }
        return (Test-IsReservedVolume -Label $di.VolumeLabel -TotalBytes $di.TotalSize)
    } catch {}
    return $false
}

# ==============================================================================
# BACKUP EM REDE SEM SENHA (igual ao FIBS 2.0.2 original)
# O FIBS rodava como programa aberto NO USUARIO LOGADO e gravava na pasta de rede com
# o login dele. O MEC Shield roda como servico (conta do servidor): primeiro tenta
# gravar direto; se a pasta nao aceitar a conta do servidor, entrega a copia ao
# usuario logado no servidor, que grava com o mesmo acesso do Explorer.
# Nenhum usuario ou senha e pedido, guardado ou enviado.
# ==============================================================================
function Test-IsSystemAccount {
    try { return [System.Security.Principal.WindowsIdentity]::GetCurrent().IsSystem } catch { return $false }
}

# Falta de permissao (e nao rede fora do ar): repetir com a mesma conta nao adianta.
function Test-IsAccessDeniedError {
    param($ErrorRecord)
    $ex = $ErrorRecord.Exception
    if ($ex -is [System.UnauthorizedAccessException]) { return $true }
    $msg = "$($ex.Message) $($ex.InnerException.Message)"
    return ($msg -match '(?i)access.*denied|acesso.*negado')
}

# Usuarios com sessao aberta no servidor (donos do explorer.exe), sem repetir.
function Get-LoggedOnUsers {
    $users = @()
    try {
        foreach ($p in @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop)) {
            try {
                $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
                if ($o.ReturnValue -eq 0 -and -not [string]::IsNullOrWhiteSpace($o.User)) {
                    $u = if ([string]::IsNullOrWhiteSpace($o.Domain)) { "$($o.User)" } else { "$($o.Domain)\$($o.User)" }
                    if ($users -notcontains $u) { $users += $u }
                }
            } catch {}
        }
    } catch {}
    # Sem virgula: ",@()" viraria "1 usuario vazio" em @(Get-LoggedOnUsers)
    return $users
}

# Script que roda NA SESSAO DO USUARIO: copia, confere SHA-256 e aplica a retencao do
# prefixo no destino (a conta do servidor pode nao ter permissao de apagar la). MODE=PROBE
# so grava, le e apaga um arquivo de teste. Resposta: OK|FALHA <TAB> usuario <TAB> ...
function Get-UserSessionCopyScript {
    return @'
param([string]$JobFile)
$res = $null
$quem = try { [Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { "?" }
$r = "FALHA`t$quem`tpedido ilegivel"
try {
    $job = @{}
    foreach ($l in (Get-Content -LiteralPath $JobFile -Encoding UTF8)) { $p = $l.Split("`t", 2); if ($p.Count -eq 2) { $job[$p[0]] = $p[1] } }
    $res = $job["RESULT"]
    $dest = $job["DESTDIR"]
    if (-not (Test-Path -LiteralPath $dest)) { New-Item -ItemType Directory -Path $dest -Force -ErrorAction Stop | Out-Null }
    if ($job["MODE"] -eq "PROBE") {
        $probe = Join-Path $dest (".mecshield_teste_{0}.tmp" -f [Guid]::NewGuid().ToString("N"))
        try {
            [IO.File]::WriteAllText($probe, "MEC Shield")
            if ([IO.File]::ReadAllText($probe) -ne "MEC Shield") { throw "arquivo de teste lido com conteudo diferente" }
        } finally { Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue }
        $r = "OK`t$quem`t`t0"
    } else {
        $final = Join-Path $dest (Split-Path $job["SRC"] -Leaf)
        Copy-Item -LiteralPath $job["SRC"] -Destination $final -Force -ErrorAction Stop
        # SHA-256 pelo .NET: Get-FileHash nao existe no PowerShell 2/3
        $fs = [IO.File]::Open($final, 'Open', 'Read', 'Read')
        $alg = [Security.Cryptography.SHA256]::Create()
        try { $sha = [BitConverter]::ToString($alg.ComputeHash($fs)).Replace("-", "") } finally { $alg.Clear(); $fs.Close() }
        if ($sha -ne $job["SHA"]) {
            Remove-Item -LiteralPath $final -Force -ErrorAction SilentlyContinue
            throw "SHA-256 da copia nao confere com a origem (arquivo chegou alterado)"
        }
        $pfx = [regex]::Escape($job["PREFIX"])
        $keep = 30; [void][int]::TryParse($job["KEEP"], [ref]$keep); if ($keep -lt 1) { $keep = 1 }
        $velhos = @(Get-ChildItem -LiteralPath $dest -File -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -match "^${pfx}[-_]\d{4,}\.(GZ|zip)$" -or $_.Name -match "^${pfx}[-_]\d{8}_\d{6}\.(GZ|zip)$"
        } | Sort-Object LastWriteTime -Descending | Select-Object -Skip $keep)
        foreach ($f in $velhos) { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue }
        $r = "OK`t$quem`t$final`t$($velhos.Count)"
    }
} catch {
    $r = "FALHA`t$quem`t$(($_.Exception.Message -replace '[\r\n\t]+', ' '))"
}
if ($res) {
    [IO.File]::WriteAllText("$res.tmp", $r)
    Move-Item -LiteralPath "$res.tmp" -Destination $res -Force
}
'@
}

# Roda o script na sessao do usuario por uma tarefa agendada temporaria ("somente
# quando o usuario estiver logado": o Windows nao pede senha) e espera a resposta.
function Invoke-AsLoggedOnUser {
    param([string]$User, [string]$HelperFile, [string]$JobFile, [string]$ResultFile, [int]$TimeoutSec = 900)
    $nome = "Copia_Rede_" + [Guid]::NewGuid().ToString("N").Substring(0, 12)
    try {
        $act = New-ScheduledTaskAction -Execute "powershell.exe" -Argument ("-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"{0}`" -JobFile `"{1}`"" -f $HelperFile, $JobFile)
        $set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Seconds ($TimeoutSec + 120))
        try {
            $prn = New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Highest
            Register-ScheduledTask -TaskPath "\MEC_Shield\" -TaskName $nome -Action $act -Principal $prn -Settings $set -Force -ErrorAction Stop | Out-Null
        } catch {
            # Privilegio maximo recusado para este usuario: roda no nivel normal dele
            $prn = New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Limited
            Register-ScheduledTask -TaskPath "\MEC_Shield\" -TaskName $nome -Action $act -Principal $prn -Settings $set -Force -ErrorAction Stop | Out-Null
        }
        Start-ScheduledTask -TaskPath "\MEC_Shield\" -TaskName $nome -ErrorAction Stop
        $limite = (Get-Date).AddSeconds($TimeoutSec)
        while ((Get-Date) -lt $limite -and -not (Test-Path $ResultFile)) { Start-Sleep -Seconds 2 }
    } finally {
        try { Unregister-ScheduledTask -TaskPath "\MEC_Shield\" -TaskName $nome -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    }
}

# Copia (ou testa, com -Probe) um destino de rede pela sessao de cada usuario logado,
# ate um conseguir. Devolve Ok, User, FinalPath, Removed e Message.
function Copy-ViaLoggedOnUser {
    param(
        [string]$DestDir,
        [string]$SourceFile = "",
        [string]$Prefix = "BKP_SISMOTEL",
        [int]$Keep = 30,
        [string]$ExpectedSha = "",
        [switch]$Probe,
        [int]$TimeoutSec = 900,
        [string]$WorkRoot = ""
    )
    $users = @(Get-LoggedOnUsers)
    if ($users.Count -eq 0) {
        return [PSCustomObject]@{ Ok = $false; User = ""; FinalPath = ""; Removed = 0; Message = "nenhum usuario logado no servidor para fazer a copia pela sessao dele" }
    }
    $base = if ([string]::IsNullOrWhiteSpace($WorkRoot)) { Join-Path $env:ProgramData "MEC_Shield\rede" } else { $WorkRoot }
    $falhas = @()
    foreach ($u in $users) {
        $jobDir = Join-Path $base ([Guid]::NewGuid().ToString("N"))
        try {
            New-Item -ItemType Directory -Path $jobDir -Force -ErrorAction Stop | Out-Null
            & icacls.exe $jobDir /grant "${u}:(OI)(CI)M" /Q 2>&1 | Out-Null
            if (-not $Probe) { & icacls.exe $SourceFile /grant "${u}:(R)" /Q 2>&1 | Out-Null }
            $helper = Join-Path $jobDir "copia_rede.ps1"
            [System.IO.File]::WriteAllText($helper, (Get-UserSessionCopyScript), [System.Text.Encoding]::ASCII)
            $jobFile = Join-Path $jobDir "pedido.txt"
            $resFile = Join-Path $jobDir "resposta.txt"
            $modo = if ($Probe) { "PROBE" } else { "COPY" }
            $linhas = @("MODE`t$modo", "DESTDIR`t$DestDir", "SRC`t$SourceFile", "PREFIX`t$Prefix", "KEEP`t$Keep", "SHA`t$ExpectedSha", "RESULT`t$resFile")
            [System.IO.File]::WriteAllText($jobFile, ($linhas -join "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
            Invoke-AsLoggedOnUser -User $u -HelperFile $helper -JobFile $jobFile -ResultFile $resFile -TimeoutSec $TimeoutSec
            if (-not (Test-Path $resFile)) { $falhas += "${u}: sem resposta em $TimeoutSec s"; continue }
            $p = ([System.IO.File]::ReadAllText($resFile)).Split("`t")
            if ($p[0] -eq "OK") {
                $removidos = 0; if ($p.Count -ge 4) { [void][int]::TryParse($p[3], [ref]$removidos) }
                $final = if ($p.Count -ge 3) { $p[2] } else { "" }
                return [PSCustomObject]@{ Ok = $true; User = $p[1]; FinalPath = $final; Removed = $removidos; Message = "OK" }
            }
            $falhas += "$($p[1]): $(if ($p.Count -ge 3) { $p[2] } else { 'falha sem detalhe' })"
        } catch {
            $falhas += "${u}: $($_.Exception.Message)"
        } finally {
            try { Remove-Item $jobDir -Recurse -Force -ErrorAction SilentlyContinue } catch {}
        }
    }
    return [PSCustomObject]@{ Ok = $false; User = ""; FinalPath = ""; Removed = 0; Message = ($falhas -join " | ") }
}

# Teste de gravacao real no destino, executado pela interface como SYSTEM (tarefa
# agendada temporaria): mesma logica do backup automatico -- direto pela conta do
# servidor e, se ela for barrada, pela sessao do usuario logado.
function Invoke-NetworkAccessTest {
    param([string[]]$Destinations)
    $results = @()
    foreach ($d in $Destinations) {
        if ([string]::IsNullOrWhiteSpace($d)) { continue }
        $dest = (Resolve-MappedDrivePath $d.Trim()).TrimEnd('\', '/')
        $probe = Join-Path $dest (".mecshield_teste_{0}.tmp" -f ([Guid]::NewGuid().ToString("N")))
        $direto = ""
        try {
            if (-not (Test-Path $dest)) { throw "pasta inacessivel ou inexistente para a conta do servidor" }
            [System.IO.File]::WriteAllText($probe, "MEC Shield - teste de gravacao $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
            $lido = [System.IO.File]::ReadAllText($probe)
            if ($lido -notmatch '^MEC Shield - teste de gravacao') { throw "arquivo de teste lido com conteudo diferente" }
        } catch {
            $direto = "$($_.Exception.Message)".Trim()
            if ([string]::IsNullOrWhiteSpace($direto)) { $direto = "$_" }
        } finally {
            try { if (Test-Path $probe) { Remove-Item $probe -Force -ErrorAction SilentlyContinue } } catch {}
        }
        if ([string]::IsNullOrWhiteSpace($direto)) {
            $results += [PSCustomObject]@{ Destination = $dest; Ok = $true; Message = "Gravacao direta pelo servico: OK (funciona 24h, mesmo sem ninguem logado)." }
            continue
        }
        if (-not (Test-IsSystemAccount)) {
            $results += [PSCustomObject]@{ Destination = $dest; Ok = $false; Message = "Falha: $direto" }
            continue
        }
        $v = Copy-ViaLoggedOnUser -DestDir $dest -Probe -TimeoutSec 120
        if ($v.Ok) {
            $results += [PSCustomObject]@{ Destination = $dest; Ok = $true; Message = "Grava pelo usuario logado ($($v.User)), igual ao FIBS antigo, sem senha. Precisa de alguem logado no servidor para a copia de rede (o backup local continua 24h)." }
        } else {
            $results += [PSCustomObject]@{ Destination = $dest; Ok = $false; Message = "Servico: $direto | Usuario logado: $($v.Message)" }
        }
    }
    return $results
}

# Pedido/resposta do teste em arquivos texto (TAB) na pasta temp da instalacao, que so
# SYSTEM e Administradores gravam.
function Invoke-NetworkAccessTestFromRequest {
    param([string]$RequestFile, [string]$ResultFile)
    $dests = @()
    if (Test-Path $RequestFile) {
        foreach ($line in (Get-Content $RequestFile -Encoding UTF8)) {
            $p = $line.Split("`t", 2)
            if ($p.Count -eq 2 -and $p[0] -eq "DEST") { $dests += $p[1].Trim() }
        }
        Remove-Item $RequestFile -Force -ErrorAction SilentlyContinue
    }
    $ident = try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { "desconhecida" }
    $out = @("IDENT`t$ident")
    if ($dests.Count -eq 0) {
        $out += "FALHA`t-`tPedido de teste vazio ou ilegivel."
    } else {
        foreach ($r in (Invoke-NetworkAccessTest -Destinations $dests)) {
            $status = if ($r.Ok) { "OK" } else { "FALHA" }
            $out += "$status`t$($r.Destination)`t$(($r.Message -replace '[\r\n\t]+', ' '))"
        }
    }
    Write-TextFileAtomic -Path $ResultFile -Content ($out -join "`r`n")
}

# ==============================================================================
# MODULO DE VERIFICACAO DE INTEGRIDADE DO BACKUP
# ==============================================================================
# Um backup que chega corrompido no destino e pior que backup nenhum, porque passa
# a falsa sensacao de protecao. Aqui o GZ e aberto e LIDO de volta antes de o .fbk
# de origem ser descartado, e cada copia gravada e conferida byte a byte contra a
# origem antes de a politica de retencao apagar os backups antigos.
#
# NOTA TECNICA: no .NET Framework, ler o stream de uma entrada de GZ ate o fim NAO
# valida o CRC32 (isso so acontece no .NET moderno), e a propriedade Crc32 da entrada
# nao existe nesta versao. Por isso a conferencia e feita com SHA-256 do conteudo
# descompactado contra o hash do .fbk original: detecta corrupcao silenciosa, e a
# abertura do arquivo detecta truncamento (diretorio central ausente).

# SHA-256 direto pelo .NET. NAO usar Get-FileHash: ele nao existe no PowerShell 2/3 e o
# -InputStream so existe a partir do 5.0. Em servidor com PowerShell 4 (Windows Server
# 2012 R2) o portao do GZ falhava em TODA rotina e nenhum backup era gravado.
function Get-Sha256OfStream {
    param([System.IO.Stream]$Stream)
    $alg = [System.Security.Cryptography.SHA256]::Create()
    try { return [System.BitConverter]::ToString($alg.ComputeHash($Stream)).Replace("-", "") }
    finally { $alg.Clear() }
}

function Get-Sha256OfFile {
    param([string]$Path)
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        try { return Get-Sha256OfStream -Stream $fs } finally { $fs.Close() }
    } catch { return $null }
}

function Test-BackupGzIntegrity {
    param(
        [string]$GzPath,
        [string]$ExpectedEntryName,
        [long]$ExpectedSize,
        [string]$ExpectedSha256
    )
    $zip = $null
    try {
        try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue } catch {}

        # Truncamento / GZ invalido estoura logo aqui (fim do diretorio central ausente)
        $zip = [System.IO.Compression.ZipFile]::OpenRead($GzPath)

        $entry = $zip.Entries | Where-Object { $_.Name -eq $ExpectedEntryName } | Select-Object -First 1
        if ($null -eq $entry) {
            return @{ Ok = $false; Reason = "A entrada '$ExpectedEntryName' nao existe dentro do GZ." }
        }
        if ($entry.Length -ne $ExpectedSize) {
            return @{ Ok = $false; Reason = "Tamanho descompactado divergente: GZ diz $($entry.Length) bytes, o .fbk tinha $ExpectedSize bytes." }
        }

        $stream = $entry.Open()
        try { $hash = Get-Sha256OfStream -Stream $stream }
        finally { $stream.Close() }

        if ($hash -ne $ExpectedSha256) {
            return @{ Ok = $false; Reason = "SHA-256 do conteudo descompactado nao confere com o .fbk original (corrupcao silenciosa)." }
        }
        return @{ Ok = $true; Reason = "Conteudo conferido por SHA-256." }
    } catch {
        return @{ Ok = $false; Reason = "Nao foi possivel abrir/ler o GZ: $_" }
    } finally {
        if ($null -ne $zip) { try { $zip.Dispose() } catch {} }
    }
}

# Funcao de Gestao da Numeracao Sequencial Limpa (ex: BKP_SISMOTEL-0000.GZ)
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
                    $files = Get-ChildItem -Path $resolved -Filter "$Prefix-*.*" -File -ErrorAction SilentlyContinue
                    foreach ($f in $files) {
                        if ($f.Name -match "^$([regex]::Escape($Prefix))-(\d+)\.(zip|gz|rar|fbk)$") {
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

    # O numero so e gravado como consumido quando o backup termina com sucesso
    # (Save-BackupSequenceNumber). Rotinas que falham nao "queimam" numeros.
    return $candidate
}

function Save-BackupSequenceNumber {
    param([string]$Prefix, [int]$UsedNumber, [string]$SequenceFilePath)
    try {
        Invoke-WithMecLock -Name "State" -Script {
            $seqData = @{}
            if (Test-Path $SequenceFilePath) {
                $raw = Get-Content $SequenceFilePath -Raw -Encoding UTF8 | ConvertFrom-Json
                if ($null -ne $raw) {
                    foreach ($prop in $raw.psobject.Properties) { $seqData[$prop.Name] = [int]$prop.Value }
                }
            }
            $next = $UsedNumber + 1
            if (-not $seqData.ContainsKey($Prefix) -or [int]$seqData[$Prefix] -lt $next) {
                $seqData[$Prefix] = $next
            }
            Save-JsonState -Path $SequenceFilePath -Data $seqData
        }
    } catch {
        Log-Message "Aviso ao gravar a sequencia de backups: $_"
    }
}

# Politica de retencao: mantem os $Keep arquivos mais recentes do prefixo na pasta.
# Usada nos destinos configurados, no destino alternativo e no fail-safe (antes o
# fail-safe nao tinha retencao e enchia o disco do banco de dados).
# Backups do prefixo na pasta, do mais recente para o mais antigo. Outros prefixos e
# arquivos que nao sao backup nunca entram na lista (nunca sao apagados).
function Get-PrefixBackupFiles {
    param([string]$Directory, [string]$Prefix)
    $escapedPrefix = [regex]::Escape($Prefix)
    return @(Get-ChildItem -Path $Directory -File -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match "^${escapedPrefix}[-_]\d{4,}\.(GZ|zip)$" -or $_.Name -match "^${escapedPrefix}[-_]\d{8}_\d{6}\.(GZ|zip)$"
    } | Sort-Object LastWriteTime -Descending)
}

function Invoke-RetentionPolicy {
    param([string]$Directory, [string]$Prefix, [int]$Keep)
    if ($Keep -lt 1) { $Keep = 1 }
    try {
        Log-Message "Aplicando politica de retencao em $Directory (Manter ultimos $Keep backups do prefixo '$Prefix')..."
        $backupFiles = @(Get-PrefixBackupFiles -Directory $Directory -Prefix $Prefix)

        if ($backupFiles.Count -gt $Keep) {
            foreach ($oldFile in ($backupFiles | Select-Object -Skip $Keep)) {
                Log-Message "Excluindo backup excedente antigo: $($oldFile.Name)"
                Remove-Item $oldFile.FullName -Force -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Log-Message "Aviso na politica de retencao em $($Directory): $_"
    }
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

# Credenciais do Firebird por variavel de ambiente (suportado pelo cliente Firebird
# 2.5+): gbak/gfix/gstat deixam de receber -password na linha de comando.
function Get-FirebirdEnvironment {
    param([string]$User, [string]$Password)
    return @{ ISC_USER = $User; ISC_PASSWORD = $Password }
}

# Funcao de Envio de Notificacao por E-mail (SMTP)
# Envio de e-mail com retentativas. O resultado sai em $global:mailSent.
# Isso importa porque os cooldowns anti-flood (12h para falha, prazo do monitor para
# destino ausente) so podem ser armados APOS um envio confirmado: armar antes fazia um
# alerta perdido por queda momentanea de internet silenciar o proximo aviso por horas,
# justamente no cenario em que o cliente mais precisa ser avisado.
function Send-MailWithRetry {
    param(
        [System.Net.Mail.MailMessage]$Mail,
        [string]$SmtpServer,
        [int]$Port,
        [bool]$UseSsl,
        $Pref,
        [int]$Attempts = 3
    )
    # IMPORTANTE: o resultado sai por $global:mailSent, NAO pelo valor de retorno
    # (padrao mantido por compatibilidade com os chamadores).
    $global:mailSent = $false

    $smtpPassword = $null
    if (-not [string]::IsNullOrWhiteSpace($Pref.SmtpUser) -and -not [string]::IsNullOrWhiteSpace($Pref.SmtpPass)) {
        $smtpPassword = Unprotect-String $Pref.SmtpPass
        if ($null -eq $smtpPassword) {
            Log-Message "ERRO: a senha SMTP criptografada (DPAPI) nao pode ser aberta neste servidor. Redigite a senha em Preferencias. E-mail nao enviado."
            return
        }
    }

    # TLS: com usuario/senha, a conexao na porta 587 sempre tenta STARTTLS, para a
    # senha nao trafegar em texto puro. So cai para texto puro se o servidor declarar
    # que NAO suporta TLS (nao por erro de certificado).
    $useTls = $UseSsl -or ($Port -eq 587 -and $null -ne $smtpPassword)
    # Certificado invalido e tolerado por padrao para evitar falha em relays locais/webmail
    # e apenas durante este envio -- antes a validacao ficava desligada no processo
    # inteiro, inclusive para o download do LiveUpdate.
    $allowInvalidCert = $true
    if ($null -ne $Pref.SmtpAllowInvalidCertificate) {
        $allowInvalidCert = [bool]$Pref.SmtpAllowInvalidCertificate
    }
    $previousCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback

    try {
        [System.Net.ServicePointManager]::SecurityProtocol = `
            [System.Net.ServicePointManager]::SecurityProtocol `
            -bor [System.Net.SecurityProtocolType]::Tls12 `
            -bor [System.Net.SecurityProtocolType]::Tls11
    } catch {}

    try {
        if ($allowInvalidCert) {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        }
        for ($try = 1; $try -le $Attempts; $try++) {
            $smtp = $null
            try {
                $smtp = New-Object System.Net.Mail.SmtpClient($SmtpServer, $Port)
                $smtp.EnableSsl = $useTls
                $smtp.DeliveryMethod = [System.Net.Mail.SmtpDeliveryMethod]::Network
                $smtp.UseDefaultCredentials = $false
                if ($null -ne $smtpPassword) {
                    $smtp.Credentials = New-Object System.Net.NetworkCredential($Pref.SmtpUser, $smtpPassword)
                }
                $smtp.Timeout = 25000
                $smtp.Send($Mail)
                $global:mailSent = $true
                return
            } catch {
                $inner = if ($_.Exception -and $_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
                $semTls = ($useTls -and -not $UseSsl -and ("$($_.Exception.Message) $inner" -match 'secure connections|conex.es seguras|STARTTLS'))
                if ($semTls) {
                    Log-Message "Aviso: o servidor SMTP $SmtpServer nao oferece TLS (STARTTLS). Enviando sem criptografia; recomenda-se um servidor com TLS."
                    $useTls = $false
                    $try--
                } elseif ($try -lt $Attempts) {
                    $espera = 15 * $try
                    Log-Message "Aviso: tentativa $try de envio de e-mail falhou ($inner). Nova tentativa em ${espera}s..."
                    Start-Sleep -Seconds $espera
                } else {
                    Log-Message "ERRO: todas as $Attempts tentativas de envio de e-mail falharam. Ultimo erro: $inner"
                }
            } finally {
                if ($null -ne $smtp) { try { $smtp.Dispose() } catch {} }
            }
        }
    } finally {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $previousCallback
    }
}

function Test-WithinCooldown {
    param($Timestamp, [double]$Hours)
    if ($null -eq $Timestamp -or [string]::IsNullOrWhiteSpace("$Timestamp")) { return $false }
    try {
        $dt = [DateTime]::Parse("$Timestamp")
        $elapsed = ((Get-Date) - $dt).TotalHours
        return ($elapsed -ge 0 -and $elapsed -lt $Hours)
    } catch { return $false }
}

function New-TaskNotificationState {
    return [PSCustomObject]@{
        InFailureState      = $false
        LastFailureAlert    = $null
        InWarningState      = $false
        LastWarningAlert    = $null
        ConsecutiveFailures = 0
        LastConfigWarning   = $null
    }
}

# backup_state.json = { "Tasks": { "<tarefa>": { ...estado... } } }
# O formato antigo (um unico estado para tudo) e migrado para a tarefa atual.
function Get-TaskNotificationState {
    param([string]$TaskName)
    $stateFile = Join-Path $scriptDir "backup_state.json"
    $state = New-TaskNotificationState
    try {
        if (Test-Path $stateFile) {
            $raw = Get-Content $stateFile -Raw -Encoding UTF8 | ConvertFrom-Json
            $src = $null
            if ($null -ne $raw.Tasks -and $null -ne $raw.Tasks.$TaskName) {
                $src = $raw.Tasks.$TaskName
            } elseif ($null -eq $raw.Tasks -and $null -ne $raw.PSObject.Properties["InFailureState"]) {
                $src = $raw
            }
            if ($null -ne $src) {
                foreach ($prop in $state.PSObject.Properties.Name) {
                    if ($null -ne $src.PSObject.Properties[$prop]) { $state.$prop = $src.$prop }
                }
            }
        }
    } catch {
        Log-Message "Aviso: estado de notificacoes ilegivel; iniciando estado limpo para '$TaskName'."
    }
    if ($null -eq $state.ConsecutiveFailures) { $state.ConsecutiveFailures = 0 }
    return $state
}

function Save-TaskNotificationState {
    param([string]$TaskName, $State)
    $stateFile = Join-Path $scriptDir "backup_state.json"
    try {
        Invoke-WithMecLock -Name "State" -Script {
            $all = @{}
            if (Test-Path $stateFile) {
                try {
                    $raw = Get-Content $stateFile -Raw -Encoding UTF8 | ConvertFrom-Json
                    if ($null -ne $raw.Tasks) {
                        foreach ($p in $raw.Tasks.PSObject.Properties) { $all[$p.Name] = $p.Value }
                    }
                } catch {}
            }
            $all[$TaskName] = $State
            Save-JsonState -Path $stateFile -Data @{ Tasks = $all } -Depth 6
        }
    } catch {
        Log-Message "Aviso ao gravar o estado de notificacoes: $_"
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

        # Estado anti-flood POR TAREFA. Antes era um estado unico para todas: o sucesso
        # de uma tarefa zerava o cooldown da outra (alerta a cada 2h alternando horas
        # pares/impares) e uma segunda falha diferente ficava escondida por 12h.
        $state = Get-TaskNotificationState -TaskName $TaskName

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
                if ($WarningDests.Count -gt 0) { $state.InWarningState = $true }
                Log-Message "Sistema recuperado de falha anterior. Backup voltou a funcionar normalmente (notificacao suprimida - Zero Spam)."
                Save-TaskNotificationState -TaskName $TaskName -State $state
                return
            } elseif ($WarningDests.Count -eq 0 -and $state.InWarningState -eq $true) {
                # RECUPERADO de destino de rede offline - silencioso, apenas limpa o estado
                $state.InWarningState = $false
                $state.LastWarningAlert = $null
                Log-Message "Destino de rede reconectado. Sincronizacao voltou ao normal (notificacao suprimida - Zero Spam)."
                Save-TaskNotificationState -TaskName $TaskName -State $state
                return
            } else {
                if ($WarningDests.Count -gt 0) {
                    # Destino externo/rede inacessivel: registra estado mas NAO envia e-mail imediato.
                    # O alerta so sera enviado pelo Monitor de Rede apos 24h continuas sem sincronizacao,
                    # evitando notificacoes desnecessarias por quedas rapidas de rede ou computador desligado temporariamente.
                    $state.InWarningState = $true
                    Log-Message "AVISO SILENCIOSO DE REDE: Destino(s) externo(s) inacessivel(is) nesta rotina. Monitorando acumulo (alerta sera enviado somente apos 24h continuas sem sincronizacao)."
                    Log-Message "Destinos nao sincronizados: $($WarningDests -join ' | ')"
                    Save-TaskNotificationState -TaskName $TaskName -State $state
                    return
                } else {
                    # Silencio Total em Rotinas Normais com Sucesso (Zero Spam - nao envia e-mail em rotinas normais)
                    $state.InWarningState = $false
                    Log-Message "Notificacao por e-mail suprimida (Backup de rotina 100% gravado com sucesso - Zero Spam)."
                    Save-TaskNotificationState -TaskName $TaskName -State $state
                    return
                }
            }
        } elseif ($Status -eq "FALHA") {
            $state.InFailureState = $true
            $state.ConsecutiveFailures++

            if ($pref.NotifyOnFailure -ne $true) {
                Save-TaskNotificationState -TaskName $TaskName -State $state
                return
            }

            # Validacao de Cooldown Anti-Flood (nao mandar a cada hora se falhar repetidamente)
            if (Test-WithinCooldown -Timestamp $state.LastFailureAlert -Hours $cooldownHours) {
                $hoursSince = ((Get-Date) - [DateTime]::Parse("$($state.LastFailureAlert)")).TotalHours
                Log-Message "ANTI-FLOOD ATIVO: Alerta de falha ja enviado ha $([Math]::Round($hoursSince, 1))h. E-mail suprimido para nao lotar a caixa de entrada (Cooldown: ${cooldownHours}h)."
                Save-TaskNotificationState -TaskName $TaskName -State $state
                return
            }

            $shouldSend = $true
            $subjectTag = "[MEC ALERTA CRITICO]"
            $statusTitle = "FALHA CRITICA NA ROTINA DE BACKUP"
            $bannerBg = "#dc2626"
            $bannerType = "ALERT"

            # NAO armar $state.LastFailureAlert aqui: o cooldown de ${cooldownHours}h so e
            # gravado depois que o envio for confirmado, la no fim desta funcao.
            Save-TaskNotificationState -TaskName $TaskName -State $state
        } elseif ($Status -eq "AVISO") {
            # Problema de configuracao que NAO impediu o backup (ex.: banco encontrado
            # fora do caminho configurado). Avisa no maximo 1 vez a cada 24h por tarefa,
            # sem mexer no estado de falha.
            if ($pref.NotifyOnFailure -ne $true) { return }
            if (Test-WithinCooldown -Timestamp $state.LastConfigWarning -Hours 24) {
                Log-Message "Aviso de configuracao ja enviado nas ultimas 24h. E-mail suprimido (Zero Spam)."
                return
            }
            $shouldSend = $true
            $subjectTag = "[MEC AVISO]"
            $statusTitle = "ATENCAO: CONFIGURACAO PRECISA DE REVISAO"
            $bannerBg = "#d97706"
            $bannerType = "WARNING"
        }

        if (-not $shouldSend) { return }

        # Tudo que vem de mensagens de erro, caminhos e config entra no HTML escapado.
        $clientNameHtml = ConvertTo-HtmlSafe $clientName
        $BodyDetails = ConvertTo-HtmlSafe $BodyDetails
        $DbPath = ConvertTo-HtmlSafe $DbPath
        $SuccessDests = @($SuccessDests | ForEach-Object { ConvertTo-HtmlSafe $_ })
        $WarningDests = @($WarningDests | ForEach-Object { ConvertTo-HtmlSafe $_ })

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

        $isOddTask = ($TaskName -match "EXTERN" -or $TaskName -eq "BKP_EXTERNO")
        $taskBadgeHtml = if ($isOddTask) {
            "<span style='display:inline-block; margin-left:8px; padding:3px 8px; border-radius:4px; font-size:11.5px; font-weight:700; background-color:#1e3a8a; color:#93c5fd; border:1px solid #3b82f6;'>C&Oacute;PIA EXTERNA (HORAS &Iacute;MPARES)</span>"
        } else {
            "<span style='display:inline-block; margin-left:8px; padding:3px 8px; border-radius:4px; font-size:11.5px; font-weight:700; background-color:#064e3b; color:#6ee7b7; border:1px solid #10b981;'>BACKUP LOCAL NO SERVIDOR (HORAS PARES)</span>"
        }

        $isNetFailure = ($isOddTask -or $SubjectInfo -match "Externo|Rede|Terminal" -or $BodyDetails -match "CONECTIVIDADE|REDE EXTERNA")
        $recActionsHtml = if ($isNetFailure) {
            @"
            <div style='margin-bottom:8px;'>
              <strong>1. Terminal da Recep&ccedil;&atilde;o:</strong> Verificar se o computador de destino est&aacute; ligado, n&atilde;o est&aacute; hibernando e com cabo de rede conectado.
            </div>
            <div style='margin-bottom:8px;'>
              <strong>2. Compartilhamento do Windows:</strong> Confirmar se a pasta de backup continua compartilhada na rede e acess&iacute;vel.
            </div>
            <div style='margin-bottom:8px;'>
              <strong>3. Permiss&atilde;o de Grava&ccedil;&atilde;o:</strong> A pasta precisa aceitar grava&ccedil;&atilde;o da conta do servidor (servi&ccedil;o SYSTEM). Na pasta do terminal, as abas Compartilhamento e Seguran&ccedil;a precisam liberar grava&ccedil;&atilde;o (ex.: Todos). Use o bot&atilde;o &quot;Testar Acesso como SYSTEM&quot; na tarefa.
            </div>
            <div>
              <strong>4. Banco de Dados Local:</strong> Nenhuma a&ccedil;&atilde;o necess&aacute;ria no banco Firebird (o banco est&aacute; 100% &iacute;ntegro e seguro no servidor).
            </div>
"@
        } else {
            @"
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
"@
        }

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
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0; font-weight:800; color:#ffffff; font-size:16px;">$clientNameHtml</td>
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
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0; font-weight:800; color:#ffffff; font-size:15px;">$TaskName $taskBadgeHtml</td>
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
                        <td bgcolor='#1e293b' style='background-color:#1e293b; padding:6px 0; color:#cbd5e1; font-size:14px;'>$GbakDurationStr (GBAK) &bull; $ZipDurationStr (.GZ)</td>
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
                        <td bgcolor='#1e293b' style='background-color:#1e293b; padding:6px 0; color:#94a3b8; font-weight:600;'>Arquivo Final (.GZ):</td>
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
          $(if (($Status -eq "FALHA" -or $Status -eq "AVISO") -and $BodyDetails) {
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
                    $recActionsHtml
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
                    <li style='margin-bottom:4px;'><strong>Permiss&atilde;o:</strong> A pasta n&atilde;o aceita grava&ccedil;&atilde;o do servidor. Libere nas abas Compartilhamento e Seguran&ccedil;a da pasta (ex.: Todos com Modificar).</li>
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
                MEC Shield Enterprise v$($script:EngineVersion) &bull; FIBS Prote&ccedil;&atilde;o 24/7 &bull; Desenvolvido por Rodrigo
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
                Save-TaskNotificationState -TaskName $TaskName -State $state
                Log-Message "Cooldown anti-flood de ${cooldownHours}h armado (a partir da entrega confirmada)."
            } elseif ($Status -eq "AVISO") {
                $state.LastConfigWarning = (Get-Date).ToString("o")
                Save-TaskNotificationState -TaskName $TaskName -State $state
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
                A instala&ccedil;&atilde;o do sistema corporativo <strong style="color:#10b981;">FIBS MEC Shield Enterprise (v$($script:EngineVersion))</strong> foi conclu&iacute;da com &ecirc;xito neste servidor. Esta nova gera&ccedil;&atilde;o substitui integralmente as rotinas legadas e traz uma arquitetura avan&ccedil;ada de conting&ecirc;ncia concebida sob medida para o regime ininterrupto (24/7) de mot&eacute;is, blindando o banco de dados do <strong>Sismotel</strong> com prote&ccedil;&atilde;o em m&uacute;ltiplas camadas e sem nenhum impacto na agilidade da recep&ccedil;&atilde;o.
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
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0; color:#34d399; font-weight:700; font-size:13.5px;">v$($script:EngineVersion) &bull; Enterprise Shield</td>
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
                MEC Shield Enterprise v$($script:EngineVersion) &bull; FIBS Prote&ccedil;&atilde;o 24/7 &bull; Desenvolvido por Rodrigo
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
        [string]$TaskName,          # nome real da tarefa (ex.: BKP_EXTERNO) - usado no caminho do log
        [string]$TerminalName = "", # NetworkTerminalName configurado junto das credenciais
        [string]$FailureReason = ""
    )
    # Rotulo curto para assunto: prefere o nome do terminal, cai para o da tarefa
    $rotulo = if (-not [string]::IsNullOrWhiteSpace($TerminalName)) { $TerminalName } else { $TaskName }
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

        $clientNameHtml = ConvertTo-HtmlSafe $clientName
        $Destination = ConvertTo-HtmlSafe $Destination
        $FailureReason = ConvertTo-HtmlSafe $FailureReason
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
                        <td bgcolor="#1e293b" style="padding:7px 0; font-weight:800; color:#ffffff; font-size:16px;">$clientNameHtml</td>
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
                        <td bgcolor="#1e293b" style="padding:7px 0; color:#94a3b8; font-weight:600;">Terminal Configurado:</td>
                        <td bgcolor="#1e293b" style="padding:7px 0; font-weight:700; color:#fbbf24; font-size:14.5px;">$(if ([string]::IsNullOrWhiteSpace($TerminalName)) { "(nao definido nas credenciais)" } else { $TerminalName })</td>
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
                MEC Shield Enterprise v$($script:EngineVersion) &bull; FIBS Prote&ccedil;&atilde;o 24/7 &bull; Desenvolvido por Rodrigo
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
        $identificacao = if ($rotulo -ne $TaskName -and -not [string]::IsNullOrWhiteSpace($TerminalName)) {
            "$rotulo / $TaskName"
        } else { $TaskName }
        $mail.Subject = "[MEC ALERTA] $identificacao sem backup ha ${daysStr} - $clientName ($hostName)"
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
# Grava no network_tracker.json apenas as entradas que este processo atualizou,
# relendo o arquivo sob trava: monitor horario e rotina de backup nao apagam mais
# as atualizacoes um do outro.
function Save-NetworkTrackerEntries {
    param([hashtable]$Entries, [string[]]$Keys)
    $trackerFile = Join-Path $scriptDir "network_tracker.json"
    try {
        Invoke-WithMecLock -Name "State" -Script {
            $current = @{}
            if (Test-Path $trackerFile) {
                try { $current = ConvertTo-HashtableCompat (Get-Content $trackerFile -Raw -Encoding UTF8 | ConvertFrom-Json) } catch {}
            }
            foreach ($k in ($Keys | Select-Object -Unique)) {
                if ($Entries.ContainsKey($k)) { $current[$k] = $Entries[$k] }
            }
            Save-JsonState -Path $trackerFile -Data $current
        }
    } catch {
        Log-Message "Aviso ao gravar o rastreador de destinos: $_"
    }
}

function Test-ExternalDestinationsHealth {
    param (
        [string]$TaskName = "BKP_EXTERNO",
        [string[]]$Destinations = @(),
        [string]$FailureReason = "",
        # Derrubar conexoes antigas com o host (erro 1219) so e seguro quando nenhum
        # backup esta copiando para ele. O modo monitor so passa este switch se
        # conseguir a trava de backup.
        [switch]$AllowDisconnect
    )
    try {
        if ($null -eq $global:configData -or $null -eq $global:configData.Tasks) {
            if (Test-Path $configFile) {
                try { $global:configData = Get-Content $configFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch {}
            }
        }
        if ($null -eq $global:configData -or $null -eq $global:configData.Tasks) { return }

        $tConf = $global:configData.Tasks | Where-Object { $_.TaskName -eq $TaskName } | Select-Object -First 1
        if ($null -eq $tConf) {
            $tConf = $global:configData.Tasks | Where-Object { $_.TaskName -match "EXTERN" } | Select-Object -First 1
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

        $netTerm = if (-not [string]::IsNullOrWhiteSpace($tConf.NetworkTerminalName)) { $tConf.NetworkTerminalName } else { "" }
        $nomeTarefaReal = if (-not [string]::IsNullOrWhiteSpace($tConf.TaskName)) { $tConf.TaskName } else { $TaskName }

        $touchedKeys = @()
        foreach ($dest in $destsToCheck) {
            $destTrim = $dest.TrimEnd('\', '/')
            if ([string]::IsNullOrWhiteSpace($destTrim)) { continue }
            if (Test-IsSystemReservedDrive -Path $destTrim) { continue }

            # Traducao automatica de unidade mapeada (ex: Z:\... -> \\servidor\pasta\...) para servicos Windows (SYSTEM)
            $destResolved = Resolve-MappedDrivePath $destTrim
            if ($destResolved -ne $destTrim) {
                $destTrim = $destResolved.TrimEnd('\', '/')
            }

            if (-not $netTracker.ContainsKey($destTrim)) { $netTracker[$destTrim] = @{} }
            $touchedKeys += $destTrim
            $detectedReason = $FailureReason

            $authFailureReason = ""

            # Checagem Fisica Real de Arquivos .GZ no destino
            $realLastBackupTime = $null
            $destAccessible = $false
            try {
                if (Test-Path $destTrim) {
                    $destAccessible = $true
                    $existingGzs = @(Get-ChildItem -Path "$destTrim\*" -Include "*.GZ", "*.zip" -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
                    if ($existingGzs.Count -gt 0) {
                        $realLastBackupTime = $existingGzs[0].LastWriteTime
                    }
                }
            } catch {}

            $hoursSince = 0
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
                    # Pasta acessivel mas 0 arquivos .GZ encontrados (pasta limpa, formatada ou recem criada)
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
                    $detectedReason = if (-not [string]::IsNullOrWhiteSpace($authFailureReason)) { $authFailureReason } else { "Terminal offline, pasta descompartilhada, ou pasta sem permissao para o servico e ninguem logado no servidor." }
                }
            }

            if ($hoursSince -ge $alertHours) {
                $lastAlert = if ($netTracker[$destTrim].LastAlert) { [DateTime]::Parse($netTracker[$destTrim].LastAlert) } else { [DateTime]::MinValue }
                if (((Get-Date) - $lastAlert).TotalHours -ge $alertHours) {
                    Log-Message "ALERTA CRITICO DISPARADO (prazo ${alertHours}h): Destino '$destTrim' sem backup valido ha $([Math]::Round($hoursSince, 1)) horas (limite ${alertHours}h). Motivo: $detectedReason"
                    $global:mailSent = $false
                    Send-NetworkFailureAlert -Destination $destTrim -DelayHours ([Math]::Round($hoursSince)) -TaskName $nomeTarefaReal -TerminalName $netTerm -FailureReason $detectedReason
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

        Save-NetworkTrackerEntries -Entries $netTracker -Keys @($touchedKeys)
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
    
    # A restauracao de teste tem ao mesmo tempo o FBK extraido e o FDB restaurado:
    # exige 2.5x o banco (minimo 4096 MB), mais a reserva de 5 GB do disco (no disco
    # do banco, max(5 GB, 10%))
    # (antes 1.5x, e a auditoria das 03:30 podia zerar o disco do banco).
    $minRequiredMB = Get-RequiredFreeMB -DbSizeMB $DbSizeMB -Factor 2.5 -MinMB 4096
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
    
    $drives = [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.IsReady -and ($_.DriveType -eq 'Fixed' -or $_.DriveType -eq 'Removable') -and -not (Test-IsSystemReservedDrive -Path $_.Name) }
    
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
        $reqDbDrive = Get-RequiredFreeMB -DbSizeMB $DbSizeMB -Factor 2.5 -MinMB 4096 -DriveTotalMB ($sameDrive.TotalSize / 1MB) -IsDbDrive $true
        if ($freeMB -ge $reqDbDrive) {
            $sandboxPath = Join-Path $scriptDir "_temp_audit"
            return [PSCustomObject]@{ Path = $sandboxPath; Drive = $sameDrive.Name; FreeMB = $freeMB; RequiredMB = $reqDbDrive; Status = "OK" }
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

# Estado da auditoria diaria em arquivo proprio (audit_state.json). Antes a data
# era gravada reescrevendo o config.json inteiro, concorrendo com a interface.
function Get-AuditState {
    $f = Join-Path $scriptDir "audit_state.json"
    $st = [PSCustomObject]@{ LastAuditDate = ""; LastResult = ""; ConsecutiveInconclusive = 0; LastInconclusiveAlert = $null }
    try {
        if (Test-Path $f) {
            $raw = Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json
            foreach ($prop in $st.PSObject.Properties.Name) {
                if ($null -ne $raw.PSObject.Properties[$prop]) { $st.$prop = $raw.$prop }
            }
        } elseif ($null -ne $global:configData -and $null -ne $global:configData.Preferences -and -not [string]::IsNullOrWhiteSpace($global:configData.Preferences.LastAuditDate)) {
            # Migracao: instalacoes antigas guardavam a data no config.json
            $st.LastAuditDate = "$($global:configData.Preferences.LastAuditDate)"
        }
    } catch {}
    if ($null -eq $st.ConsecutiveInconclusive) { $st.ConsecutiveInconclusive = 0 }
    return $st
}

function Save-AuditState {
    param($State)
    $f = Join-Path $scriptDir "audit_state.json"
    try {
        Invoke-WithMecLock -Name "State" -Script { Save-JsonState -Path $f -Data $State }
    } catch {
        Log-Message "Aviso ao gravar o estado da auditoria: $_"
    }
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
        [string]$AuditLogSnippet,
        [string]$Headline = "ANOMALIA DETECTADA NO FIREBIRD",
        [string]$Diagnosis = ""
    )
    $headlineHtml = ConvertTo-HtmlSafe $Headline
    $diagnosisHtml = ConvertTo-HtmlSafe $Diagnosis
    $AuditLogSnippet = ConvertTo-HtmlSafe $AuditLogSnippet
    $DbPath = ConvertTo-HtmlSafe $DbPath
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
              &#9679; AUDITORIA PREVENTIVA &bull; $headlineHtml
            </td>
          </tr>

          <!-- TITULO -->
          <tr>
            <td bgcolor="#111827" style="background-color:#111827; padding:22px 28px 10px 28px;">
              <h2 style="margin:0 0 6px 0; color:#fef2f2; font-size:20px; font-weight:700;">Inconsist&ecirc;ncia Identificada na Auditoria em Sandbox</h2>
              <p style="margin:0; color:#cbd5e1; font-size:14px; line-height:1.65;">
                A auditoria preventiva di&aacute;ria executada em sandbox isolado identificou anomalias no banco de dados Firebird. <span style="color:#34d399; font-weight:600;">O banco ativo no motel permanece operando normalmente sem paradas</span>, por&eacute;m requer interven&ccedil;&atilde;o t&eacute;cnica preventiva programada da equipe MEC para preservar a integridade dos dados.
              </p>
              $(if ($diagnosisHtml) { "<p style='margin:12px 0 0 0; padding:12px 14px; background-color:#450a0a; border-left:4px solid #ef4444; border-radius:6px; color:#fecaca; font-size:14px; line-height:1.6;'><strong>Diagn&oacute;stico:</strong> $diagnosisHtml</p>" })
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
                        <td bgcolor="#1e293b" style="background-color:#1e293b; padding:6px 0; font-weight:800; color:#ffffff; font-size:16px;">$(ConvertTo-HtmlSafe $cleanClient)</td>
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
                MEC Shield Enterprise v$($script:EngineVersion) &bull; FIBS Prote&ccedil;&atilde;o 24/7 &bull; Desenvolvido por Rodrigo
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
        $mail.Subject = "[ALERTA DE BANCO SISMOTEL] $Headline - $cleanClient ($hostName)"
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

# ------------------------------------------------------------------------------
# Classificadores das saidas do Firebird (funcoes puras, cobertas pelo Pester).
# Regra de ouro: "nao consegui verificar" NUNCA vira "banco integro".
# ------------------------------------------------------------------------------
function Test-FirebirdAccessProblem {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    return ($Text -match 'user name and password|password are not defined|Unable to complete network request|connection rejected|unavailable database|no permission for|Access is denied|Acesso negado|login|cannot attach|lock time-out')
}

function Get-GstatHeaderInfo {
    param([string]$Output)
    $info = [PSCustomObject]@{ Ok = $false; Oldest = [long]0; Next = [long]0; Gap = [long]0; Reason = "" }
    $mOld = [regex]::Match("$Output", 'Oldest transaction\s+(\d+)')
    $mNext = [regex]::Match("$Output", 'Next transaction\s+(\d+)')
    if ($mOld.Success -and $mNext.Success) {
        $info.Ok = $true
        $info.Oldest = [long]$mOld.Groups[1].Value
        $info.Next = [long]$mNext.Groups[1].Value
        $info.Gap = $info.Next - $info.Oldest
    } else {
        $trecho = "$Output".Trim()
        if ($trecho.Length -gt 300) { $trecho = $trecho.Substring(0, 300) }
        $info.Reason = "gstat -h nao retornou o cabecalho do banco (saida: '$trecho')."
    }
    return $info
}

# Resultado da restauracao de teste (gbak -rep) na sandbox.
#  OK             : codigo 0, FDB criado e sem "ERROR" na saida
#  INCONCLUSIVO   : o Firebird recusou acesso (senha, servico, permissao)
#  NAO_RESTAURAVEL: qualquer outra falha -> o arquivo de backup nao serve para desastre
function Get-RestoreVerdict {
    param($ExitCode, [bool]$FdbExists, [long]$FdbSize, [string]$Output)
    $temErro = ("$Output" -match '(?im)^\s*gbak:\s*ERROR|ERROR:')
    if ($ExitCode -eq 0 -and $FdbExists -and $FdbSize -gt 0 -and -not $temErro) {
        return [PSCustomObject]@{ Verdict = "OK"; Reason = "Restauracao de teste concluida." }
    }
    if (Test-FirebirdAccessProblem $Output) {
        return [PSCustomObject]@{ Verdict = "INCONCLUSIVO"; Reason = "O Firebird recusou a restauracao de teste por acesso/credencial (codigo $ExitCode)." }
    }
    return [PSCustomObject]@{ Verdict = "NAO_RESTAURAVEL"; Reason = "O backup mais recente NAO restaurou (gbak codigo $ExitCode, FDB criado: $FdbExists)." }
}

# Resultado da validacao gfix -v -full no banco restaurado.
function Get-GfixVerdict {
    param($ExitCode, [string]$Output)
    $rec = 0; $pag = 0
    $mRec = [regex]::Match("$Output", 'Number of record level errors\s*:\s*(\d+)')
    $mPag = [regex]::Match("$Output", 'Number of database page errors\s*:\s*(\d+)')
    if ($mRec.Success) { $rec = [int]$mRec.Groups[1].Value }
    if ($mPag.Success) { $pag = [int]$mPag.Groups[1].Value }
    $corrupcao = ("$Output" -match 'checksum error|wrong page type|corrupt')
    if ($corrupcao -and $pag -eq 0) { $pag = 1 }

    if ($rec -gt 0 -or $pag -gt 0) {
        return [PSCustomObject]@{ Verdict = "CORROMPIDO"; RecordErrors = $rec; PageErrors = $pag; Reason = "gfix encontrou $rec erro(s) de registro e $pag erro(s) de pagina." }
    }
    if (($mRec.Success -or $mPag.Success) -and $ExitCode -eq 0) {
        return [PSCustomObject]@{ Verdict = "OK"; RecordErrors = 0; PageErrors = 0; Reason = "gfix sem erros." }
    }
    # Firebird 2.5 nao imprime nada quando a validacao passa limpa.
    $semTextoDeErro = -not ("$Output" -match '(?i)error|failed|unable|denied|negado|falha|not found|nao encontrado')
    if ($ExitCode -eq 0 -and $semTextoDeErro) {
        return [PSCustomObject]@{ Verdict = "OK"; RecordErrors = 0; PageErrors = 0; Reason = "gfix sem erros." }
    }
    if (Test-FirebirdAccessProblem $Output) {
        return [PSCustomObject]@{ Verdict = "INCONCLUSIVO"; RecordErrors = 0; PageErrors = 0; Reason = "gfix nao conseguiu acessar o banco restaurado (codigo $ExitCode)." }
    }
    return [PSCustomObject]@{ Verdict = "INCONCLUSIVO"; RecordErrors = 0; PageErrors = 0; Reason = "gfix terminou com codigo $ExitCode sem relatorio de validacao." }
}

# Le o cabecalho do banco ativo (gstat -h). Isolado em funcao para os testes.
function Invoke-GstatHeader {
    param([string]$GstatExe, [string]$DbPath, [hashtable]$Environment = @{})
    $saved = @{}
    foreach ($k in $Environment.Keys) { $saved[$k] = [Environment]::GetEnvironmentVariable($k, "Process"); [Environment]::SetEnvironmentVariable($k, [string]$Environment[$k], "Process") }
    try { return (& "$GstatExe" -h "$DbPath" 2>&1 | Out-String) }
    catch { return "$_" }
    finally { foreach ($k in $saved.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k], "Process") } }
}

function Invoke-DatabaseHealthAudit {
    param (
        [string]$TaskName
    )
    $script:LastAuditVerdict = "INCONCLUSIVO"

    Log-Message "--------------------------------------------------------------------------------"
    Log-Message "[AUDITORIA DE SAUDE] Iniciando diagnostico preventivo de integridade do Sismotel..."

    if ($null -eq $global:configData) { $global:configData = Read-ConfigData }
    if ($null -eq $global:configData) {
        Log-Message "[AUDITORIA ERRO] Arquivo config.json nao pode ser carregado."
        return $script:LastAuditVerdict
    }

    $pref = $global:configData.Preferences
    $task = $global:configData.Tasks | Where-Object { $_.TaskName -eq $TaskName } | Select-Object -First 1
    if ($null -eq $task) {
        $task = $global:configData.Tasks | Select-Object -First 1
    }
    if ($null -eq $task) {
        Log-Message "[AUDITORIA ERRO] Nenhuma tarefa encontrada para auditoria."
        return $script:LastAuditVerdict
    }

    $clientName = if (-not [string]::IsNullOrWhiteSpace($pref.ClientName)) { $pref.ClientName } else { "CLIENTE SISMOTEL" }
    $anyDeskId = if (-not [string]::IsNullOrWhiteSpace($pref.AnyDeskId)) { $pref.AnyDeskId } else { "N&atilde;o configurado" }
    $teamViewerId = if (-not [string]::IsNullOrWhiteSpace($pref.TeamViewerId)) { $pref.TeamViewerId } else { "N&atilde;o configurado" }
    $gapThreshold = if ($null -ne $pref.AuditGapWarningThreshold -and $pref.AuditGapWarningThreshold -gt 0) { [int]$pref.AuditGapWarningThreshold } else { 200000 }

    $verdict = "OK"
    $motivos = @()
    $recordErrors = 0
    $pageErrors = 0
    $gfixLog = ""
    $oldestTrans = 0
    $nextTrans = 0
    $transGap = 0

    # 1. Ferramentas Firebird
    $gbakExe = "$($task.GbakPath)"
    if ([string]::IsNullOrWhiteSpace($gbakExe) -or -not (Test-Path $gbakExe)) {
        foreach ($cand in @("C:\Program Files\Firebird\Firebird_2_5\bin\gbak.exe", "C:\Program Files (x86)\Firebird\Firebird_2_5\bin\gbak.exe")) {
            if (Test-Path $cand) { $gbakExe = $cand; break }
        }
    }
    $fbBinDir = if (-not [string]::IsNullOrWhiteSpace($gbakExe)) { Split-Path -Parent $gbakExe } else { "" }
    $gfixExe = Join-Path $fbBinDir "gfix.exe"
    $gstatExe = Join-Path $fbBinDir "gstat.exe"

    $dbUser = if (-not [string]::IsNullOrWhiteSpace($task.DbUser)) { $task.DbUser } else { "SYSDBA" }
    $dbPassRaw = if (-not [string]::IsNullOrWhiteSpace($task.DbPassword)) { $task.DbPassword } else { "masterkey" }
    $dbPass = Unprotect-String $dbPassRaw
    $fbEnv = Get-FirebirdEnvironment -User $dbUser -Password $dbPass

    $liveDb = "$($task.DatabasePath)"
    if (-not [string]::IsNullOrWhiteSpace($liveDb) -and -not (Test-Path $liveDb)) {
        if ($liveDb -like "C:\*" -and (Test-Path ("D:" + $liveDb.Substring(2)))) { $liveDb = "D:" + $liveDb.Substring(2) }
        elseif ($liveDb -like "D:\*" -and (Test-Path ("C:" + $liveDb.Substring(2)))) { $liveDb = "C:" + $liveDb.Substring(2) }
    }

    $sandboxDir = $null
    $sandboxDbPath = $null
    $extractedFbkPath = $null
    $zip = $null

    try {
        if ($null -eq $dbPass) {
            throw [System.InvalidOperationException]::new("A senha do banco (DbPassword) esta criptografada para outro computador e nao abre neste servidor.")
        }
        if ([string]::IsNullOrWhiteSpace($gbakExe) -or -not (Test-Path $gbakExe) -or -not (Test-Path $gfixExe) -or -not (Test-Path $gstatExe)) {
            throw [System.InvalidOperationException]::new("Ferramentas do Firebird (gbak/gfix/gstat) nao localizadas em '$fbBinDir'.")
        }

        # 2. ETAPA 1: cabecalho e transacoes no banco ativo (gstat -h, leitura rapida)
        Log-Message "[AUDITORIA] 1/4 - Analisando transacoes ativas via gstat -h (Zero Locks, 100% online)..."
        $gstatOut = Invoke-GstatHeader -GstatExe $gstatExe -DbPath $liveDb -Environment $fbEnv
        $hdr = Get-GstatHeaderInfo -Output $gstatOut
        if ($hdr.Ok) {
            $oldestTrans = $hdr.Oldest; $nextTrans = $hdr.Next; $transGap = $hdr.Gap
            Log-Message "[AUDITORIA] Metricas de Transacao: Oldest=$oldestTrans | Next=$nextTrans | Transaction Gap=$transGap (Alerta: $gapThreshold)"
            if ($transGap -ge $gapThreshold) {
                Log-Message "[AUDITORIA ALERTA] Transaction Gap elevado ($transGap)! Acumulo de transacoes sem commit detectado."
            }
            if ($nextTrans -ge 1500000000) {
                Log-Message "[AUDITORIA CRITICO] Next Transaction proximo ao limite de 32 bits ($nextTrans)! Executar fixtranslimit."
                $verdict = "LIMITE_TRANSACOES"
                $motivos += "O contador de transacoes ($nextTrans) esta perto do limite de 32 bits do Firebird 2.5. Ao atingir o limite o banco para de aceitar gravacoes."
            }
        } else {
            Log-Message "[AUDITORIA AVISO] $($hdr.Reason)"
            $motivos += $hdr.Reason
            $verdict = "INCONCLUSIVO"
        }

        # 3. ETAPA 2: ultimo backup local para restauracao de teste
        Log-Message "[AUDITORIA] 2/4 - Localizando ultimo arquivo de backup valido para teste fisico..."
        $searchDirs = @()
        if ($null -ne $task.Destinations) {
            foreach ($d in $task.Destinations) {
                if (-not [string]::IsNullOrWhiteSpace($d) -and -not $d.StartsWith("\\") -and (Test-Path $d)) { $searchDirs += $d }
            }
        }
        foreach ($d in @("D:\BKP_SISMOTEL", "C:\BKP_SISMOTEL")) { if (Test-Path $d) { $searchDirs += $d } }
        $searchDirs = @($searchDirs | Select-Object -Unique)

        $latestGz = $null
        foreach ($sd in $searchDirs) {
            $zips = @(Get-ChildItem -Path $sd -Filter "*.GZ" -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
            if ($zips.Count -gt 0 -and ($null -eq $latestGz -or $zips[0].LastWriteTime -gt $latestGz.LastWriteTime)) { $latestGz = $zips[0] }
        }
        if ($null -eq $latestGz) {
            throw [System.InvalidOperationException]::new("Nenhum arquivo .GZ de backup local foi encontrado para o teste de restauracao.")
        }
        Log-Message "[AUDITORIA] Arquivo de backup selecionado: $($latestGz.FullName) ($([math]::Round($latestGz.Length / 1MB, 2)) MB)"

        # 4. ETAPA 3: disco da sandbox
        $dbSizeMB = 0
        try { $dbSizeMB = [math]::Round(((Get-Item $liveDb -ErrorAction Stop).Length / 1MB), 2) }
        catch { $dbSizeMB = [math]::Round(($latestGz.Length / 1MB) * 1.3, 2) }
        $sandboxInfo = Get-OptimalSandboxDir -DbPath $liveDb -DbSizeMB $dbSizeMB -ConfiguredDestinations $task.Destinations
        if ($sandboxInfo.Status -eq "INSUFFICIENT_SPACE") {
            throw [System.InvalidOperationException]::new("Espaco em disco insuficiente para a sandbox (minimo $($sandboxInfo.RequiredMB) MB). O teste de restauracao nao foi feito.")
        }
        $sandboxDir = $sandboxInfo.Path
        Log-Message "[AUDITORIA] 3/4 - Ambiente Sandbox Isolado: $($sandboxInfo.Drive) | Caminho: $sandboxDir | Espaco Livre: $($sandboxInfo.FreeMB) MB"
        if (Test-Path $sandboxDir) {
            Get-ChildItem -Path $sandboxDir -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        } else {
            New-Item -ItemType Directory -Path $sandboxDir -Force | Out-Null
        }
        $sandboxDbPath = Join-Path $sandboxDir "audit_sandbox_$(Get-Date -Format 'yyyyMMdd_HHmmss').fdb"

        # Extrai o FBK
        Log-Message "[AUDITORIA] Extraindo .FBK do backup para o sandbox..."
        try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue } catch {}
        try {
            $zip = [System.IO.Compression.ZipFile]::OpenRead($latestGz.FullName)
            $fbkEntry = $zip.Entries | Where-Object { $_.Name.EndsWith(".fbk", [StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1
            if ($null -eq $fbkEntry) { throw "o arquivo .FBK nao existe dentro de $($latestGz.Name)" }
            $extractedFbkPath = Join-Path $sandboxDir $fbkEntry.Name
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($fbkEntry, $extractedFbkPath, $true)
        } catch {
            # Arquivo de backup que nem abre e, por definicao, um backup inutilizavel
            $verdict = "NAO_RESTAURAVEL"
            $motivos += "O arquivo $($latestGz.Name) nao pode ser aberto/extraido: $($_.Exception.Message)"
            throw
        } finally {
            if ($null -ne $zip) { try { $zip.Dispose() } catch {}; $zip = $null }
        }
        Log-Message "[AUDITORIA] Arquivo FBK extraido ($([math]::Round((Get-Item $extractedFbkPath).Length / 1MB, 2)) MB). Iniciando restauracao de teste (gbak -rep)..."

        # Restauracao de teste
        $gbakArgs = @("-rep", "-v", "`"$extractedFbkPath`"", "`"$sandboxDbPath`"")
        $rGbak = Invoke-ExternalTool -FilePath $gbakExe -Arguments ($gbakArgs -join " ") -Environment $fbEnv -TimeoutMs 7200000
        $saidaGbak = @("$($rGbak.StdOut)" -split "`r?`n")
        $restoreText = "$($rGbak.StdErr)`n" + (($saidaGbak | Select-Object -Last 40) -join "`n")
        if ($rGbak.TimedOut) { $restoreText += "`nRestauracao de teste excedeu 2 horas e foi interrompida." }
        Remove-Item $extractedFbkPath -Force -ErrorAction SilentlyContinue; $extractedFbkPath = $null

        $fdbExists = Test-Path $sandboxDbPath
        $fdbSize = if ($fdbExists) { (Get-Item $sandboxDbPath).Length } else { 0 }
        $rv = Get-RestoreVerdict -ExitCode $rGbak.ExitCode -FdbExists $fdbExists -FdbSize $fdbSize -Output $restoreText
        if ($rv.Verdict -ne "OK") {
            $gfixLog = $restoreText
            if ($rv.Verdict -eq "NAO_RESTAURAVEL") { $verdict = "NAO_RESTAURAVEL" } elseif ($verdict -eq "OK") { $verdict = "INCONCLUSIVO" }
            $motivos += $rv.Reason
            Log-Message "[AUDITORIA FALHA] $($rv.Reason)"
        } else {
            Log-Message "[AUDITORIA] Banco restaurado na sandbox com sucesso ($([math]::Round($fdbSize / 1MB, 2)) MB). Arquivo de backup 100% legivel!"

            # 5. ETAPA 4: validacao profunda (gfix -v -full -no_update)
            Log-Message "[AUDITORIA] 4/4 - Executando gfix -v -full -no_update no banco de sandbox isolado..."
            $rGfix = Invoke-ExternalTool -FilePath $gfixExe -Arguments "-v -full -no_update `"$sandboxDbPath`"" -Environment $fbEnv -TimeoutMs 3600000
            $gfixLog = "$($rGfix.StdErr)$($rGfix.StdOut)"
            if ($rGfix.TimedOut) { $gfixLog += "`nValidacao gfix excedeu 1 hora e foi interrompida." }

            $gv = Get-GfixVerdict -ExitCode $rGfix.ExitCode -Output $gfixLog
            $recordErrors = $gv.RecordErrors
            $pageErrors = $gv.PageErrors
            Log-Message "[AUDITORIA] Resultado da Verificacao Fisica: Record Errors = $recordErrors | Page Errors = $pageErrors ($($gv.Reason))"
            if ($gv.Verdict -eq "CORROMPIDO") {
                $verdict = "CORROMPIDO"; $motivos += $gv.Reason
            } elseif ($gv.Verdict -eq "INCONCLUSIVO") {
                if ($verdict -eq "OK") { $verdict = "INCONCLUSIVO" }
                $motivos += $gv.Reason
            }
        }
    } catch {
        $msg = if ($_.Exception) { $_.Exception.Message } else { "$_" }
        Log-Message "[AUDITORIA ERRO] $msg"
        if ($verdict -eq "OK") { $verdict = "INCONCLUSIVO" }
        if (-not ($motivos | Where-Object { "$_".Contains($msg) })) { $motivos += $msg }
        if ([string]::IsNullOrWhiteSpace($gfixLog)) { $gfixLog = $msg }
    } finally {
        # 6. LIMPEZA COMPLETA E GARANTIDA DO AMBIENTE SANDBOX
        if ($null -ne $zip) { try { $zip.Dispose() } catch {} }
        if (-not [string]::IsNullOrWhiteSpace($sandboxDir) -and (Split-Path $sandboxDir -Leaf) -eq "_temp_audit" -and (Test-Path $sandboxDir)) {
            Log-Message "[AUDITORIA] Limpando ambiente sandbox temporario..."
            Remove-Item $sandboxDir -Recurse -Force -ErrorAction SilentlyContinue
            Log-Message "[AUDITORIA] Limpeza da sandbox concluida."
        }
    }

    # 7. REGISTRO E NOTIFICACAO (Zero Spam, mas nunca silencio diante de risco real)
    $script:LastAuditVerdict = $verdict
    $auditState = Get-AuditState
    $auditState.LastAuditDate = (Get-Date -Format "yyyy-MM-dd")
    $auditState.LastResult = $verdict
    $diagnostico = ($motivos | Select-Object -Unique) -join " "

    $headline = $null
    if ($verdict -eq "OK") {
        $auditState.ConsecutiveInconclusive = 0
        $gapTxt = if ($transGap -ge $gapThreshold) { "Transaction Gap em $transGap (notificacao de e-mail silenciada)." } else { "Transaction Gap normal ($transGap)." }
        Log-Message "[AUDITORIA 100% SUCESSO] Backup restaurado e banco FISICAMENTE INTEGRO! 0 erros de registro, 0 erros de paginas. $gapTxt"
        Log-Message "[AUDITORIA ZERO SPAM] Operacao 100% silenciosa no e-mail conforme politica corporativa."
    } elseif ($verdict -eq "INCONCLUSIVO") {
        $auditState.ConsecutiveInconclusive = [int]$auditState.ConsecutiveInconclusive + 1
        Log-Message "[AUDITORIA INCONCLUSIVA] A integridade NAO foi comprovada hoje ($($auditState.ConsecutiveInconclusive) dia(s) seguido(s)). Motivo: $diagnostico"
        # Falha persistente (2 auditorias seguidas) avisa; um soluco isolado nao.
        if ($auditState.ConsecutiveInconclusive -ge 2 -and -not (Test-WithinCooldown -Timestamp $auditState.LastInconclusiveAlert -Hours 20)) {
            $headline = "AUDITORIA NAO CONSEGUE VALIDAR O BANCO"
        }
    } else {
        $auditState.ConsecutiveInconclusive = 0
        $headline = switch ($verdict) {
            "NAO_RESTAURAVEL"   { "BACKUP NAO RESTAURAVEL" }
            "CORROMPIDO"        { "CORRUPCAO FISICA DETECTADA NO FIREBIRD" }
            "LIMITE_TRANSACOES" { "LIMITE DE TRANSACOES DO FIREBIRD PROXIMO" }
            default             { "ANOMALIA DETECTADA NO FIREBIRD" }
        }
        Log-Message "[AUDITORIA ALERTA CRITICO] $headline. $diagnostico Disparando notificacao para a equipe tecnica..."
    }

    if ($null -ne $headline) {
        $global:mailSent = $false
        Send-AuditAlertNotification -ClientName $clientName -AnyDeskId $anyDeskId -TeamViewerId $teamViewerId -DbPath $liveDb -RecordErrors $recordErrors -PageErrors $pageErrors -TransactionGap $transGap -NextTransaction $nextTrans -AuditLogSnippet $gfixLog -Headline $headline -Diagnosis $diagnostico
        if ($verdict -eq "INCONCLUSIVO" -and $global:mailSent) {
            $auditState.LastInconclusiveAlert = (Get-Date).ToString("o")
        }
    }
    Save-AuditState -State $auditState
    Log-Message "--------------------------------------------------------------------------------"
    return $verdict
}

# ==============================================================================
# CAMADA OFICIAL DE AUTO-UPDATE EM NUVEM (MEC LIVEUPDATE VIA GITHUB)
# ==============================================================================
# ------------------------------------------------------------------------------
# Seguranca do LiveUpdate: o manifesto (version.json) precisa estar ASSINADO com a
# chave privada da MEC (RSA/SHA-256). O servidor so conhece a chave PUBLICA
# (liveupdate_pubkey.xml, instalada junto com o sistema). Assim, mesmo que o
# repositorio publico seja comprometido, ninguem consegue fazer os servidores dos
# clientes executarem um instalador falso como SYSTEM.
# Ferramentas: tools\liveupdate_gerar_chaves.ps1 e tools\liveupdate_assinar_release.ps1
# ------------------------------------------------------------------------------
function Get-LiveUpdatePayload {
    param($Manifest)
    $setupSha = "$($Manifest.setupSha256)".Trim().ToUpperInvariant()
    $engineSha = "$($Manifest.engineSha256)".Trim().ToUpperInvariant()
    return "MECSHIELD-LIVEUPDATE|v1|$("$($Manifest.version)".Trim())|$setupSha|$engineSha"
}

function Test-LiveUpdateSignature {
    param([string]$PublicKeyXml, [string]$Payload, [string]$SignatureBase64)
    if ([string]::IsNullOrWhiteSpace($PublicKeyXml) -or [string]::IsNullOrWhiteSpace($SignatureBase64)) { return $false }
    try {
        $data = [System.Text.Encoding]::UTF8.GetBytes($Payload)
        $sig = [Convert]::FromBase64String($SignatureBase64.Trim())
        try {
            $rsa = [System.Security.Cryptography.RSA]::Create()
            $rsa.FromXmlString($PublicKeyXml)
            return [bool]$rsa.VerifyData($data, $sig, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        } catch {
            # .NET Framework sem a API moderna (HashAlgorithmName/RSASignaturePadding)
            $csp = New-Object System.Security.Cryptography.RSACryptoServiceProvider
            $csp.PersistKeyInCsp = $false
            $csp.FromXmlString($PublicKeyXml)
            return [bool]$csp.VerifyData($data, "SHA256", $sig)
        }
    } catch {
        return $false
    }
}

# Decide se deve tentar atualizar. Nunca repete a MESMA versao remota em menos de
# 24h: se algo impedir o motor de reconhecer a nova versao, o servidor nao fica
# reinstalando o pacote a cada rotina (causa da reinstalacao silenciosa em loop).
function Test-LiveUpdateAttemptAllowed {
    param($State, [string]$RemoteVersion, [switch]$Force)
    if ($Force) { return $true }
    if ("$($State.LastUpdateAttemptVersion)" -ne $RemoteVersion) { return $true }
    return -not (Test-WithinCooldown -Timestamp $State.LastUpdateAttemptAt -Hours 24)
}

function Invoke-MecLiveUpdate {
    param (
        [switch]$Force = $false
    )

    $engineVersion = $script:EngineVersion
    $webClient = $null

    try {
        if ($null -eq $global:configData -or $null -eq $global:configData.Preferences) {
            $global:configData = Read-ConfigData
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
        if (-not $updateUrl.StartsWith("https://", [StringComparison]::OrdinalIgnoreCase)) {
            Log-Message "[LIVEUPDATE BLOQUEADO] URL de atualizacao sem HTTPS ($updateUrl)."
            return
        }

        $fibsStateFile = Join-Path $scriptDir "fibs_state.json"
        $fibsState = $null
        if (Test-Path $fibsStateFile) {
            try { $fibsState = Get-Content $fibsStateFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch {}
        }
        if ($null -eq $fibsState) {
            $fibsState = [PSCustomObject]@{ WelcomeEmailSent = $false; LastUpdateCheck = "" }
        }
        # Garante as propriedades esperadas mesmo em arquivos gravados por versoes antigas
        foreach ($prop in @("WelcomeEmailSent", "LastUpdateCheck", "LastUpdateAttemptVersion", "LastUpdateAttemptAt")) {
            if ($null -eq $fibsState.PSObject.Properties[$prop]) {
                $valor = if ($prop -eq "WelcomeEmailSent") { $false } else { "" }
                $fibsState | Add-Member -NotePropertyName $prop -NotePropertyValue $valor -Force
            }
        }

        $now = Get-Date
        $lastCheckTime = [DateTime]::MinValue
        if (-not [string]::IsNullOrWhiteSpace("$($fibsState.LastUpdateCheck)")) {
            [DateTime]::TryParse("$($fibsState.LastUpdateCheck)", [ref]$lastCheckTime) | Out-Null
        }

        # Se ja verificou ha menos de 24 horas e nao e Force nem CheckUpdateOnly, aguarda o proximo ciclo diario
        if (-not $Force -and -not $CheckUpdateOnly -and ($lastCheckTime -gt [DateTime]::MinValue) -and (($now - $lastCheckTime).TotalHours -lt 24)) {
            return
        }

        # Chave publica obrigatoria: valida a assinatura RSA do manifesto
        $defaultPubKeyXml = '<RSAKeyValue><Modulus>xl4vygVDypOqBtFKnoazM8tDzvS/MubD4ZpMXt+WOFnhlZf3PHI75EEi+EMPqWK1w4MQeSGLbyk1O9uF9H+jC5UrOHZeWaHm8dL/1VR6gMyadIYDUyhf1EE+wNVA2sJptCtTnnMYFuj3YxNMshTJmC6fIzOaMHGup3G+/gZ22RhIYXB/DSRLq7rqIJ4aTlyCRPH1Vfs12q4aDM3XyvYIbb0Woms+zvieiB48mGbyWNOeXKeHnUDlgvoh83Kv2+NWA2qlix/RzNKKIR/bkTwXhGVF0ok5G7eATYGed38RkNsrlZg/KJc410iEhS++llTdTVCfkdWQG7FOnGlm8Ha1jSbBC/jTtAdsIu3+uQoByFoRoovTvnaWquWDTe5IZE/2/Y89D+kkBrI6CyMhLH20xpUcC+bTXLYQc/jgcSvEpuZRL1l0ypxm9oNh1xs8jFK82n38blszsXmiNQzWFJvW+sGXVT806ZkpFiZlrXHBfv4UWWzo+BWqY+MI3seZRK7h</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>'
        $pubKeyFile = Join-Path $scriptDir "liveupdate_pubkey.xml"
        $pubKeyXml = $null
        if (Test-Path $pubKeyFile) {
            try { $pubKeyXml = Get-Content $pubKeyFile -Raw -Encoding UTF8 } catch {}
        }
        if ([string]::IsNullOrWhiteSpace($pubKeyXml)) {
            $pubKeyXml = $defaultPubKeyXml
            try {
                [System.IO.File]::WriteAllText($pubKeyFile, $defaultPubKeyXml, [System.Text.Encoding]::UTF8)
                Log-Message "[LIVEUPDATE] Chave publica oficial auto-restaurada em: $pubKeyFile"
            } catch {
                Log-Message "[LIVEUPDATE] Usando chave publica oficial embutida em memoria."
            }
        }

        Log-Message "[LIVEUPDATE] Verificando atualizacoes online no canal oficial GitHub..."

        # Garante suporte a TLS 1.2 para comunicacao segura com o GitHub
        try {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
        } catch {}
        try {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        } catch {}
        # Nunca herdar um "aceitar qualquer certificado" de outro trecho do processo
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null

        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "MEC-Shield-LiveUpdate/$engineVersion")

        # Le manifesto remoto (version.json) com cache-buster para evitar retencao de CDN (Fastly 300s)
        $cacheBuster = [Environment]::TickCount
        $sep = if ($updateUrl.Contains("?")) { "&" } else { "?" }
        $manifestFetchUrl = "$updateUrl${sep}t=$cacheBuster"
        $manifestJson = $webClient.DownloadString($manifestFetchUrl)
        $manifest = $manifestJson | ConvertFrom-Json

        try {
            $fibsState.LastUpdateCheck = $now.ToString("yyyy-MM-dd HH:mm:ss")
            Save-JsonState -Path $fibsStateFile -Data $fibsState -Depth 5
        } catch {
            Log-Message "[LIVEUPDATE AVISO] Nao foi possivel gravar a data da verificacao: $_. A atualizacao continua."
        }

        if ($null -eq $manifest -or [string]::IsNullOrWhiteSpace($manifest.version)) {
            Log-Message "[LIVEUPDATE AVISO] Manifesto de versao invalido recebido do servidor."
            return
        }

        $remoteVer = [System.Version]$manifest.version
        $localVer = [System.Version]$engineVersion

        $localExe = Join-Path $scriptDir "MEC_Shield.exe"
        $exeVer = [System.Version]"0.0.0.0"
        if (Test-Path $localExe) {
            try {
                $fvi = (Get-Item $localExe).VersionInfo.FileVersion
                if (-not [string]::IsNullOrWhiteSpace($fvi)) { $exeVer = [System.Version]$fvi }
            } catch {}
        }

        $remoteVer3 = [System.Version]"$($remoteVer.Major).$($remoteVer.Minor).$([Math]::Max(0, $remoteVer.Build))"
        $exeVer3 = [System.Version]"$($exeVer.Major).$($exeVer.Minor).$([Math]::Max(0, $exeVer.Build))"
        $exeNeedsUpdate = ($exeVer.Major -eq 0) -or ($exeVer3 -lt $remoteVer3)
        $engineNeedsUpdate = ($remoteVer -gt $localVer)

        if (-not $engineNeedsUpdate -and -not $exeNeedsUpdate -and -not $Force) {
            Log-Message "[LIVEUPDATE] FIBS esta 100% atualizado (Motor: v$engineVersion, Interface: v$exeVer). Nenhuma acao necessaria."
            return
        }

        # Assinatura do manifesto: sem assinatura valida, nada e baixado.
        $payload = Get-LiveUpdatePayload -Manifest $manifest
        if (-not (Test-LiveUpdateSignature -PublicKeyXml $pubKeyXml -Payload $payload -SignatureBase64 "$($manifest.signature)")) {
            Log-Message "[LIVEUPDATE BLOQUEADO] O manifesto v$($manifest.version) NAO tem assinatura valida da MEC. Atualizacao recusada por seguranca."
            return
        }

        if (-not (Test-LiveUpdateAttemptAllowed -State $fibsState -RemoteVersion "$($manifest.version)" -Force:$Force)) {
            Log-Message "[LIVEUPDATE] A versao v$($manifest.version) ja foi aplicada/tentada nas ultimas 24h. Nova tentativa somente apos esse prazo."
            return
        }
        $fibsState.LastUpdateAttemptVersion = "$($manifest.version)"
        $fibsState.LastUpdateAttemptAt = (Get-Date).ToString("o")
        try { Save-JsonState -Path $fibsStateFile -Data $fibsState -Depth 5 } catch {}

        $statusDesc = if ($engineNeedsUpdate) { "Motor: v$engineVersion -> v$($manifest.version)" } else { "Interface defasada: v$exeVer -> v$($manifest.version)" }
        Log-Message "[LIVEUPDATE] Atualizacao assinada detectada: v$($manifest.version) ($statusDesc). Baixando..."

        # Prepara pasta temporaria isolada
        $tempDir = Join-Path $scriptDir "temp"
        if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir -Force | Out-Null }

        # 1) Instalador completo (Interface, Servico e Motor)
        $setupUrl = "$($manifest.setupUrl)"
        $setupSha = "$($manifest.setupSha256)".Trim().ToUpperInvariant()
        if (-not [string]::IsNullOrWhiteSpace($setupUrl) -and -not [string]::IsNullOrWhiteSpace($setupSha)) {
            $tempSetup = Join-Path $tempDir "MEC_Shield_Setup.exe"
            try {
                Log-Message "[LIVEUPDATE] Baixando instalador completo oficial v$($manifest.version)..."
                if (Test-Path $tempSetup) { Remove-Item $tempSetup -Force -ErrorAction SilentlyContinue }
                $webClient.DownloadFile($setupUrl, $tempSetup)
                $gotSha = Get-Sha256OfFile -Path $tempSetup
                if ($gotSha -ne $setupSha) {
                    Remove-Item $tempSetup -Force -ErrorAction SilentlyContinue
                    throw "SHA-256 do instalador baixado nao confere com o manifesto assinado."
                }
                Log-Message "[LIVEUPDATE] Instalador conferido (SHA-256 assinado). Executando em modo silencioso..."
                $proc = Start-Process -FilePath $tempSetup -ArgumentList "/SP- /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /DIR=`"$scriptDir`"" -PassThru
                $null = $proc.Handle
                if (-not $proc.WaitForExit(15 * 60 * 1000)) {
                    Log-Message "[LIVEUPDATE AVISO] O instalador passou de 15 minutos. Ele continua em segundo plano; esta rotina segue sem aguardar."
                    return
                }
                if ($proc.ExitCode -eq 0) {
                    Log-Message "[LIVEUPDATE 100% SUCESSO] Pacote completo v$($manifest.version) (Interface, Servico e Motor) instalado com sucesso!"
                    Remove-Item $tempSetup -Force -ErrorAction SilentlyContinue
                    return
                }
                Log-Message "[LIVEUPDATE AVISO] Instalador retornou codigo $($proc.ExitCode). Tentando atualizacao direta do motor..."
            } catch {
                Log-Message "[LIVEUPDATE AVISO] Falha no instalador completo: $_. Tentando atualizacao direta do motor..."
            }
        }

        # 2) Fallback: somente o motor (mesma exigencia de hash assinado)
        $downloadUrl = "$($manifest.downloadUrl)"
        $engineSha = "$($manifest.engineSha256)".Trim().ToUpperInvariant()
        if ([string]::IsNullOrWhiteSpace($downloadUrl) -or [string]::IsNullOrWhiteSpace($engineSha)) {
            Log-Message "[LIVEUPDATE] Manifesto sem motor avulso assinado. Nenhuma alteracao feita."
            return
        }

        $stageFile = Join-Path $tempDir "backup_engine_stage.ps1"
        if (Test-Path $stageFile) { Remove-Item $stageFile -Force -ErrorAction SilentlyContinue }
        $webClient.DownloadFile($downloadUrl, $stageFile)
        if ((Get-Sha256OfFile -Path $stageFile) -ne $engineSha) {
            Remove-Item $stageFile -Force -ErrorAction SilentlyContinue
            throw "SHA-256 do motor baixado nao confere com o manifesto assinado."
        }

        $stageContent = Get-Content $stageFile -Raw -Encoding UTF8
        $parseErrors = $null
        $null = [System.Management.Automation.PSParser]::Tokenize($stageContent, [ref]$parseErrors)
        if ($null -ne $parseErrors -and $parseErrors.Count -gt 0) {
            throw "O arquivo baixado contem $($parseErrors.Count) erro(s) de sintaxe PowerShell. Abortando com seguranca."
        }

        # Backup garantido do script atual (.bak) e troca
        $liveEngineFile = Join-Path $scriptDir "backup_engine.ps1"
        $bakEngineFile = Join-Path $scriptDir "backup_engine.ps1.bak"
        Copy-Item $liveEngineFile $bakEngineFile -Force
        Move-Item $stageFile $liveEngineFile -Force

        Log-Message "[LIVEUPDATE 100% SUCESSO] Motor FIBS atualizado com sucesso para a versao v$($manifest.version)!"
        Log-Message "[LIVEUPDATE] Backup da versao anterior salvo em: $bakEngineFile"

    } catch {
        Log-Message "[LIVEUPDATE] Checagem de atualizacoes concluida sem alteracao no sistema: $_"
    } finally {
        if ($null -ne $webClient) { $webClient.Dispose() }
    }
}

# ==============================================================================
# TRAVA DE EXECUCAO DO BACKUP (mutex do Windows + arquivo informativo p/ interface)
# ==============================================================================
$lockFile = Join-Path $scriptDir "backup_execution.lock"
$script:BackupMutex = $null
$script:BackupLockHeld = $false

# Devolve "Acquired", "Duplicate" (mesma tarefa ja rodando, disparo agendado) ou "Timeout".
function Enter-BackupLock {
    param([string]$TaskName, [switch]$Manual, [int]$MaxWaitSec = 300)
    if ($null -eq $script:BackupMutex) { $script:BackupMutex = New-MecNamedMutex -Name "Backup" }
    $waited = 0
    while ($true) {
        if (Enter-MecMutex -Mutex $script:BackupMutex -TimeoutMs 0) {
            $script:BackupLockHeld = $true
            try { Write-TextFileAtomic -Path $lockFile -Content "$TaskName | PID:$PID | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" } catch {}
            return "Acquired"
        }
        $owner = ""
        try { $owner = "$(Get-Content $lockFile -Raw -ErrorAction SilentlyContinue)".Trim() } catch {}
        $ownerTask = ""
        if ($owner -match '^(.*?)\s*\|\s*PID:(\d+)') { $ownerTask = $matches[1].Trim() }
        if (-not $Manual -and $ownerTask -eq $TaskName) { return "Duplicate" }
        if ($waited -ge $MaxWaitSec) { return "Timeout" }
        Log-Message "Aviso: Outra tarefa de backup em andamento ($owner). Aguardando liberacao ($waited/$MaxWaitSec s)..."
        if (Enter-MecMutex -Mutex $script:BackupMutex -TimeoutMs 5000) {
            $script:BackupLockHeld = $true
            try { Write-TextFileAtomic -Path $lockFile -Content "$TaskName | PID:$PID | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" } catch {}
            return "Acquired"
        }
        $waited += 5
    }
}

function Exit-BackupLock {
    if (-not $script:BackupLockHeld) { return }
    try { Remove-Item $lockFile -Force -ErrorAction SilentlyContinue } catch {}
    Exit-MecMutex $script:BackupMutex
    $script:BackupLockHeld = $false
}

function Get-DriveFreeMB {
    param([string]$Path)
    try {
        $r = [System.IO.Path]::GetPathRoot($Path)
        $d = New-Object System.IO.DriveInfo($r)
        return [math]::Round($d.AvailableFreeSpace / 1MB, 2)
    } catch { return 0 }
}

# ------------------------------------------------------------------------------
# PROTECAO DE DISCO
# O disco do banco precisa de folga para o Firebird crescer o .FDB e gravar arquivos
# de ordenacao; se ele zerar, o Sismotel para. Toda gravacao do MEC Shield nesse disco
# (copia, temporario do gbak, sandbox da auditoria, fail-safe) deixa essa folga livre.
# Reserva minima de 5 GB em QUALQUER disco (decisao do usuario): com menos que isso o
# servidor do cliente ja comeca a travar. Antes era 512 MB fora do disco do banco.
# ------------------------------------------------------------------------------
$script:MinFreeDiskMB = 5120
function Get-DiskReserveMB {
    param([double]$TotalMB, [bool]$IsDbDrive)
    if ($IsDbDrive) { return [math]::Round([Math]::Max($script:MinFreeDiskMB, $TotalMB * 0.10), 0) }
    return $script:MinFreeDiskMB
}

# Espaco para processar o banco num disco: Factor x banco (no minimo MinMB) mais a
# reserva do disco (5 GB; no disco do banco, max(5 GB, 10%)).
function Get-RequiredFreeMB {
    param([double]$DbSizeMB, [double]$Factor, [double]$MinMB = 0, [double]$DriveTotalMB = 0, [bool]$IsDbDrive = $false)
    $base = [Math]::Max($MinMB, $DbSizeMB * $Factor)
    $reserve = Get-DiskReserveMB -TotalMB $DriveTotalMB -IsDbDrive $IsDbDrive
    return [math]::Round($base + $reserve, 0)
}

function Get-DriveSpaceInfo {
    param([string]$Path)
    try {
        $d = New-Object System.IO.DriveInfo([System.IO.Path]::GetPathRoot($Path))
        if (-not $d.IsReady) { return $null }
        return [PSCustomObject]@{ FreeMB = $d.AvailableFreeSpace / 1MB; TotalMB = $d.TotalSize / 1MB }
    } catch { return $null }
}

# Espaco exigido num disco para os temporarios (Factor 1.5: FBK + GZ) ou para a sandbox
# da auditoria (Factor 2.5: FBK extraido + FDB restaurado), com a folga do disco do banco.
function Get-ProcessingRequiredMB {
    param([string]$Path, [string]$DbDrive, [double]$DbSizeMB, [double]$Factor, [double]$MinMB = 0)
    $root = [System.IO.Path]::GetPathRoot($Path)
    $info = Get-DriveSpaceInfo -Path $root
    $total = if ($null -ne $info) { $info.TotalMB } else { 0 }
    return Get-RequiredFreeMB -DbSizeMB $DbSizeMB -Factor $Factor -MinMB $MinMB -DriveTotalMB $total -IsDbDrive ($root -eq $DbDrive)
}

# Abre espaco para a nova copia ANTES de gravar num destino local: remove os backups
# mais antigos do prefixo (sempre preservando os MinKeep mais recentes) ate sobrar
# copia + folga. Se nem assim couber, a copia NAO e gravada. O "expurgo preventivo"
# anterior so reaplicava a retencao normal, que ja tinha rodado: nao liberava nada.
function Invoke-DestinationSpaceGuard {
    param(
        [string]$Directory,
        [string]$Prefix,
        [double]$IncomingMB,
        [bool]$IsDbDrive,
        [int]$MinKeep = 3,
        [scriptblock]$SpaceProvider = { param($p) Get-DriveSpaceInfo -Path $p }
    )
    $info = & $SpaceProvider $Directory
    if ($null -eq $info) {
        return [PSCustomObject]@{ Ok = $true; Removed = 0; FreeMB = -1; RequiredMB = 0; Message = "Espaco livre nao informado pelo Windows; copia segue." }
    }
    $required = [math]::Round($IncomingMB + (Get-DiskReserveMB -TotalMB $info.TotalMB -IsDbDrive $IsDbDrive), 0)
    $removed = 0
    if ($info.FreeMB -lt $required) {
        $antigos = @(Get-PrefixBackupFiles -Directory $Directory -Prefix $Prefix | Select-Object -Skip ([Math]::Max(0, $MinKeep)))
        [array]::Reverse($antigos)   # do mais antigo para o mais recente
        foreach ($f in $antigos) {
            if ($info.FreeMB -ge $required) { break }
            try {
                Remove-Item $f.FullName -Force -ErrorAction Stop
                $removed++
                Log-Message "PROTECAO DE DISCO: backup antigo removido para liberar espaco: $($f.Name) ($([math]::Round($f.Length / 1MB, 2)) MB)"
            } catch {
                Log-Message "PROTECAO DE DISCO: nao foi possivel remover $($f.Name): $_"
            }
            $info = & $SpaceProvider $Directory
            if ($null -eq $info) { break }
        }
    }
    if ($null -eq $info) {
        return [PSCustomObject]@{ Ok = $true; Removed = $removed; FreeMB = -1; RequiredMB = $required; Message = "Espaco livre nao informado pelo Windows; copia segue." }
    }
    $free = [math]::Round($info.FreeMB, 0)
    if ($info.FreeMB -ge $required) {
        return [PSCustomObject]@{ Ok = $true; Removed = $removed; FreeMB = $free; RequiredMB = $required; Message = "Espaco OK ($free MB livres, exigido $required MB)." }
    }
    $folga = if ($IsDbDrive) { "folga do disco do banco" } else { "folga minima" }
    return [PSCustomObject]@{ Ok = $false; Removed = $removed; FreeMB = $free; RequiredMB = $required; Message = "Espaco insuficiente em '$Directory': $free MB livres, exigido $required MB (copia de $([math]::Round($IncomingMB, 0)) MB + $folga). Copia nao gravada para proteger o disco." }
}

# Remove sobras de rotinas interrompidas (FBK/GZ parciais) das pastas temporarias
# exclusivas do MEC Shield. So e chamada com a trava de backup em maos.
function Clear-StaleBackupTemp {
    param([string[]]$Directories)
    foreach ($dir in ($Directories | Select-Object -Unique)) {
        if ([string]::IsNullOrWhiteSpace($dir) -or -not (Test-Path $dir)) { continue }
        $leaf = Split-Path $dir -Leaf
        if ($leaf -ne "FIBS_TEMP" -and $leaf -ne "temp_backup") { continue }
        Get-ChildItem -Path $dir -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '\.(fbk|GZ)$' -or $_.Name -match '^gbak_.*_log\.txt$' } | ForEach-Object {
            Log-Message "Limpeza: removendo sobra de rotina interrompida: $($_.FullName) ($([math]::Round($_.Length / 1MB, 2)) MB)"
            Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
        }
    }
}

# Pasta do fail-safe (ultima linha). Prefere um disco diferente do banco e so grava
# no disco do banco se, apos a copia, sobrar folga (>= 10% e >= 5 GB): encher o disco
# do Firebird derrubaria o Sismotel. Em outro disco, sobra no minimo a reserva de 5 GB.
function Select-FailSafeDirectory {
    param([string]$DbPath, [double]$GzSizeMB)
    $dbRoot = [System.IO.Path]::GetPathRoot($DbPath)
    $candidatos = @()
    if ((Test-Path "D:\") -and -not (Test-IsSystemReservedDrive -Path "D:\")) { $candidatos += "D:\BKP_SISMOTEL" }
    if (-not (Test-IsSystemReservedDrive -Path "C:\")) { $candidatos += "C:\BKP_SISMOTEL" }
    foreach ($c in $candidatos) {
        if (Test-IsSystemReservedDrive -Path $c) { continue }
        $root = [System.IO.Path]::GetPathRoot($c)
        try {
            $di = New-Object System.IO.DriveInfo($root)
            if (-not $di.IsReady) { continue }
            $freeAfterMB = ($di.AvailableFreeSpace / 1MB) - $GzSizeMB
            $minFolgaMB = Get-DiskReserveMB -TotalMB ($di.TotalSize / 1MB) -IsDbDrive $true
            if ($root -eq $dbRoot -and $freeAfterMB -lt $minFolgaMB) {
                Log-Message "Fail-safe: '$c' fica no mesmo disco do banco e ficaria com pouca folga ($([math]::Round($freeAfterMB)) MB). Disco ignorado para proteger o Firebird."
                continue
            }
            if ($freeAfterMB -lt (Get-DiskReserveMB -TotalMB ($di.TotalSize / 1MB) -IsDbDrive $false)) {
                Log-Message "Fail-safe: '$c' ficaria com menos de $($script:MinFreeDiskMB) MB livres ($([math]::Round($freeAfterMB)) MB). Disco ignorado."
                continue
            }
            return $c
        } catch {}
    }
    return $null
}

# Execucao de programa externo lendo stdout/stderr em paralelo (sem deadlock de
# buffer cheio) e com credenciais Firebird por variavel de ambiente.
function Invoke-ExternalTool {
    param([string]$FilePath, [string]$Arguments, [hashtable]$Environment = @{}, [int]$TimeoutMs = 300000)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.Arguments = $Arguments
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    foreach ($k in $Environment.Keys) { $psi.EnvironmentVariables[$k] = [string]$Environment[$k] }
    $p = [System.Diagnostics.Process]::Start($psi)
    try { $p.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal } catch {}
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $errTask = $p.StandardError.ReadToEndAsync()
    $timedOut = $false
    if (-not $p.WaitForExit($TimeoutMs)) {
        $timedOut = $true
        try { $p.Kill() } catch {}
        $p.WaitForExit()
    }
    $result = [PSCustomObject]@{
        ExitCode = $(if ($timedOut) { -1 } else { $p.ExitCode })
        TimedOut = $timedOut
        StdOut   = $outTask.Result
        StdErr   = $errTask.Result
    }
    $p.Dispose()
    return $result
}

# ==============================================================================
# Modo biblioteca (testes Pester): carrega as funcoes e para aqui, sem executar nada.
if ($env:MECSHIELD_LIBRARY_MODE -eq "1") { return }
# ==============================================================================

# INTERCEPTADOR: EXECUCAO DE AUDITORIA (-RunAuditOnly)
# O servico chama com -ScheduledAudit (uma vez por dia, respeitando a data da ultima
# auditoria). O botao da interface chama sem ele (sob demanda). Um mutex impede duas
# auditorias ao mesmo tempo disputando a mesma sandbox.
if ($RunAuditOnly) {
    Log-Message "======================================================"
    Log-Message "SOLICITACAO RECEBIDA: Executando Diagnostico de Integridade (-RunAuditOnly)..."
    $global:configData = Read-ConfigData
    if ($ScheduledAudit -and -not $ForceAudit) {
        $pAud = if ($null -ne $global:configData) { $global:configData.Preferences } else { $null }
        $auditOn = if ($null -ne $pAud -and $null -ne $pAud.EnableDailyAudit) { [bool]$pAud.EnableDailyAudit } else { $true }
        if (-not $auditOn) {
            Log-Message "Auditoria diaria desativada nas preferencias."
            exit 0
        }
        if ((Get-AuditState).LastAuditDate -eq (Get-Date -Format "yyyy-MM-dd")) {
            Log-Message "Auditoria diaria ja realizada hoje. Nada a fazer."
            exit 0
        }
    }
    $auditMutex = New-MecNamedMutex -Name "Audit"
    if (-not (Enter-MecMutex -Mutex $auditMutex -TimeoutMs 0)) {
        Log-Message "Outra auditoria ja esta em andamento. Esta solicitacao foi ignorada para nao disputar a sandbox."
        exit 0
    }
    try {
        $null = Invoke-DatabaseHealthAudit -TaskName $TaskName
    } finally {
        Exit-MecMutex $auditMutex
    }
    $resultadoAuditoria = $script:LastAuditVerdict
    Log-Message "Diagnostico de integridade concluido. Resultado: $resultadoAuditoria"
    Log-Message "======================================================"
    if ($resultadoAuditoria -eq "OK") { exit 0 } else { exit 1 }
}

# INTERCEPTADOR: VERIFICACAO DE SAUDE DO BACKUP EXTERNO (-CheckExternalHealth)
if ($CheckExternalHealth) {
    Log-Message "======================================================"
    Log-Message "MONITOR DE BACKUP: Verificando se os destinos possuem backup recente (-CheckExternalHealth)..."

    # Este monitor roda por conta propria (tarefa agendada horaria), INDEPENDENTE de o
    # backup ter rodado ou nao. E ele que cobre o caso critico: servidor desligado,
    # servico parado ou rotina travada -- situacoes em que a rotina de backup nunca
    # chega a avaliar os destinos e, sem este monitor, ninguem seria avisado.
    $global:configData = Read-ConfigData
    if ($null -eq $global:configData -or $null -eq $global:configData.Tasks) {
        Log-Message "ERRO: config.json ilegivel ou sem tarefas para monitorar."
        exit 1
    }

    # O monitor so observa: nunca derruba conexoes de rede (quem resolve o erro 1219
    # e a rotina de backup, que tem a trava) e nunca segura a trava de backup durante
    # as verificacoes (rede lenta faria a rotina seguinte desistir). Ele apenas
    # confere, por um instante, se ha backup rodando para limpar um arquivo de lock
    # orfao que a interface mostraria como "EXECUTANDO".
    try {
        $script:BackupMutex = New-MecNamedMutex -Name "Backup"
        if (Enter-MecMutex -Mutex $script:BackupMutex -TimeoutMs 0) {
            try {
                if (Test-Path $lockFile) {
                    Log-Message "Arquivo de lock orfao encontrado sem backup em execucao. Removendo: $lockFile"
                    Remove-Item $lockFile -Force -ErrorAction SilentlyContinue
                }
            } finally {
                Exit-MecMutex $script:BackupMutex
            }
        }
    } catch {}

    try {
        $checked = 0
        foreach ($t in $global:configData.Tasks) {
            if ($null -ne $t.Enabled -and [bool]$t.Enabled -eq $false) {
                Log-Message "Tarefa '$($t.TaskName)' esta pausada. Monitoramento ignorado."
                continue
            }
            if ($null -eq $t.Destinations -or @($t.Destinations).Count -eq 0) { continue }

            # Respeita o liga/desliga por tarefa (checkbox na tela de Editar Tarefa).
            # Ausente no config = ligado, para nao mudar o comportamento de quem ja esta instalado.
            $alertarEsta = if ($null -ne $t.AlertOnMissingBackup) { [bool]$t.AlertOnMissingBackup } else { $true }
            if (-not $alertarEsta) {
                Log-Message "Tarefa '$($t.TaskName)': aviso de backup ausente DESLIGADO nas configuracoes da tarefa. Ignorada pelo monitor."
                continue
            }

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
    } finally {}

    Log-Message "Monitor concluido. $checked tarefa(s) verificada(s)."
    Log-Message "======================================================"
    exit 0
}

# INTERCEPTADOR: TESTE DE ACESSO A REDE COMO SYSTEM (-TestNetworkAccess, botao da interface)
if ($TestNetworkAccess) {
    Log-Message "Teste de acesso a rede solicitado pela interface (conta: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name))."
    $testDir = Join-Path $scriptDir "temp"
    try {
        Invoke-NetworkAccessTestFromRequest -RequestFile (Join-Path $testDir "network_test_request.txt") -ResultFile (Join-Path $testDir "network_test_result.txt")
        Log-Message "Teste de acesso a rede concluido."
    } catch {
        Log-Message "Falha no teste de acesso a rede: $_"
    }
    exit 0
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

# 2. SHIELD DE CONCORRENCIA: mutex do Windows impede duas rotinas no banco ao mesmo tempo
$lockResult = Enter-BackupLock -TaskName $TaskName -Manual:$Manual -MaxWaitSec 300
if ($lockResult -eq "Duplicate") {
    Log-Message "DISPARO CONCORRENTE IGNORADO: A rotina da tarefa '$TaskName' ja esta em andamento. Execucao duplicada cancelada com seguranca."
    exit 0
}
if ($lockResult -ne "Acquired") {
    Log-Message "ALERTA DE PROTECAO: Outra rotina de backup ainda estava em andamento apos 5 minutos. Para proteger o banco em producao, esta execucao foi ignorada (o monitor horario alerta se o atraso persistir)."
    exit 0
}

# Trap global para capturar excecoes criticas
trap {
    try {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $errLine = "[$timestamp] [$TaskName] ERRO CRITICO NAO TRATADO: $_"
        Write-Host $errLine
        if ($null -ne $logFile) { Add-Content -Path $logFile -Value $errLine -Encoding UTF8 -ErrorAction SilentlyContinue }
        # Monitor, auditoria e atualizacao nao sao a rotina de backup: registram o erro
        # sem mexer no estado de falha/alerta das tarefas.
        if (-not ($CheckExternalHealth -or $RunAuditOnly -or $CheckUpdateOnly)) {
            Send-BackupNotification -Status "FALHA" -SubjectInfo "Erro Critico na Tarefa $TaskName" -BodyDetails $errLine
        }
    } catch {}

    # Limpeza tolerante a nulo: numa falha precoce (ex.: banco inacessivel) estas
    # variaveis ainda nao existem.
    foreach ($tmp in @($tempFbk, $tempGz, $gbakLog)) {
        if (-not [string]::IsNullOrWhiteSpace($tmp)) {
            try { if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue } } catch {}
        }
    }
    try { Exit-BackupLock } catch {}
    exit 1
}

Log-Message "======================================================"
Log-Message "Iniciando rotina de backup (Modo Resiliente 24/7 - Blindado)..."
$global:routineTimer = [System.Diagnostics.Stopwatch]::StartNew()
$global:gbakTimer    = New-Object System.Diagnostics.Stopwatch
$global:zipTimer     = New-Object System.Diagnostics.Stopwatch
$fbkSizeMB           = 0
$gzSizeMB           = 0

if (-not (Test-Path $configFile)) {
    Log-Message "ERRO: Arquivo config.json nao encontrado em: $configFile"
    Exit-BackupLock
    exit 1
}

# Carrega as configuracoes (com fallback para a ultima copia valida config.json.bak)
$global:configData = Read-ConfigData
if ($null -eq $global:configData) {
    Log-Message "ERRO: config.json ilegivel e sem copia de seguranca valida (config.json.bak)."
    Exit-BackupLock
    exit 1
}

# Converte credenciais em texto puro para forma criptografada (uma unica vez por servidor)
Convert-PlainPasswordsInConfig
$cfgRecarregado = Read-ConfigData
if ($null -ne $cfgRecarregado) { $global:configData = $cfgRecarregado }

# --- ENVIO DO EMAIL DE BOAS VINDAS NA PRIMEIRA EXECUCAO ---
$fibsStateFile = Join-Path $scriptDir "fibs_state.json"
$fibsState = $null
if (Test-Path $fibsStateFile) {
    try { $fibsState = Get-Content $fibsStateFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch {}
}
if ($null -eq $fibsState) {
    $fibsState = [PSCustomObject]@{ WelcomeEmailSent = $false; LastUpdateCheck = "" }
}
if (-not $fibsState.WelcomeEmailSent -and $null -ne $global:configData.Preferences) {
    $p = $global:configData.Preferences
    $ultimaTentativa = if ($null -ne $fibsState.PSObject.Properties["WelcomeEmailLastAttempt"]) { $fibsState.WelcomeEmailLastAttempt } else { $null }
    # Com o SMTP fora do ar, tenta de novo no maximo 1 vez por dia (nao atrasa cada rotina)
    if (-not [string]::IsNullOrWhiteSpace($p.SmtpServer) -and -not [string]::IsNullOrWhiteSpace($p.RecipientEmail) -and -not (Test-WithinCooldown -Timestamp $ultimaTentativa -Hours 24)) {
        Log-Message "Primeira execucao detectada. Enviando e-mail de Boas-Vindas..."
        $global:mailSent = $false
        Send-WelcomeEmail
        if ($global:mailSent) { $fibsState.WelcomeEmailSent = $true }
        $fibsState | Add-Member -NotePropertyName WelcomeEmailLastAttempt -NotePropertyValue (Get-Date).ToString("o") -Force
        try { Save-JsonState -Path $fibsStateFile -Data $fibsState -Depth 5 } catch {}
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
    Exit-BackupLock
    exit 1
}

# Verificacao de Tarefa Desativada (Pausada)
if ($null -ne $task.Enabled -and [bool]$task.Enabled -eq $false) {
    Log-Message "AVISO: A tarefa '$TaskName' esta DESATIVADA (Pausada) pelo usuario. Execucao cancelada com seguranca."
    Exit-BackupLock
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
                $minutosDesde = ((Get-Date) - [DateTime]::Parse("$prev")).TotalMinutes
                if ($minutosDesde -ge 0 -and $minutosDesde -lt $dedupeMinutes) {
                    Log-Message "DISPARO DUPLICADO IGNORADO: a tarefa '$TaskName' ja concluiu com sucesso ha $([Math]::Round($minutosDesde,1)) minuto(s) (janela de $dedupeMinutes min). Execucao redundante cancelada."
                    Exit-BackupLock
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
if ($null -eq $dbPassword) {
    $errMsg = "ERRO DE CONFIGURACAO: a senha do banco (DbPassword) da tarefa '$TaskName' esta criptografada para OUTRO computador (DPAPI) e nao abre neste servidor. Redigite a senha do banco na tarefa pelo MEC Shield."
    Log-Message $errMsg
    Send-BackupNotification -Status "FALHA" -SubjectInfo "Senha do Banco Ilegivel ($TaskName)" -BodyDetails $errMsg
    Exit-BackupLock
    exit 1
}
$fbEnv               = Get-FirebirdEnvironment -User $dbUser -Password $dbPassword
$destinations        = $task.Destinations
$keepBackupsCount    = if ($task.KeepBackupsCount -gt 0) { [int]$task.KeepBackupsCount } else { 30 }
$retryCount          = if ($task.RetryCount -gt 0) { [int]$task.RetryCount } else { 3 }
$retryInterval       = if ($task.RetryIntervalSeconds -gt 0) { [int]$task.RetryIntervalSeconds } else { 30 }
$noGarbageCollection = if ($null -ne $task.NoGarbageCollection) { [bool]$task.NoGarbageCollection } else { $true }
$convertExternal     = if ($null -ne $task.ConvertExternal) { [bool]$task.ConvertExternal } else { $true }
$runGfixSweep        = if ($null -ne $task.RunGfixSweep) { [bool]$task.RunGfixSweep } else { $false }
$runGfixValidate     = if ($null -ne $task.RunGfixValidate) { [bool]$task.RunGfixValidate } else { $false }
$networkConfigFailureReason = ""

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
    Exit-BackupLock
    exit 1
}

# 1.3 Aguarda disponibilidade do arquivo do Banco de Dados (com auto-deteccao entre C: e D:)
$dbExists = $false
$dbPathConfigurado = $dbPath
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
    Exit-BackupLock
    exit 1
}

$dbSizeMB = [math]::Round(((Get-Item $dbPath).Length / 1MB), 2)
Log-Message "Banco de dados pronto: $dbPath ($dbSizeMB MB)"

# Banco achado FORA do caminho configurado: o backup segue (melhor que nenhum), mas
# a equipe precisa saber -- pode ser uma copia antiga e nao o banco em producao.
if ($dbPath -ne $dbPathConfigurado) {
    $avisoBanco = "O banco configurado ('$dbPathConfigurado') nao foi encontrado. O backup foi feito do arquivo '$dbPath', encontrado automaticamente. Confirme se este e o banco em producao e corrija o caminho na tarefa '$TaskName'."
    Log-Message "ATENCAO: $avisoBanco"
    Send-BackupNotification -Status "AVISO" -SubjectInfo "Banco Fora do Caminho Configurado ($TaskName)" -BodyDetails $avisoBanco -DbPath $dbPath -DbSize "$dbSizeMB"
}

# 3. SHIELD DE PARTICIONAMENTO E I/O: Resolucao de destinos e isolamento de disco temporario
$destList = @()
if ($null -ne $destinations) {
    if ($destinations -is [string]) { $destList = @($destinations) } else { $destList = $destinations }
}

$resolvedDestList = @()
$missingLocalDests = @()
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
        if (Test-IsSystemReservedDrive -Path $destTrimmed) {
            # Nunca some em silencio: vira FALHA do destino e entra no alerta
            Log-Message "FALHA DE DESTINO: '$destTrimmed' esta numa particao reservada do sistema (rotulo de sistema ou menor que 1 GB). Nada foi gravado nela; corrija o destino na tarefa '$TaskName'."
            if (-not ($missingLocalDests -contains $destTrimmed)) { $missingLocalDests += $destTrimmed }
            continue
        }
        $destRoot = [System.IO.Path]::GetPathRoot($destTrimmed)
        if (-not (Test-Path $destRoot)) {
            Log-Message "FALHA DE DESTINO: A particao/unidade '$destRoot' nao existe neste computador (drive ausente ou inacessivel para a conta SYSTEM). Destino '$destTrimmed' registrado como FALHA."
            if (-not ($missingLocalDests -contains $destTrimmed)) {
                $missingLocalDests += $destTrimmed
            }
        } else {
            $resolvedDestList += $destTrimmed
        }
    }
}
if ($resolvedDestList.Count -eq 0) {
    if (-not (Test-IsSystemReservedDrive -Path "C:\BKP_SISMOTEL")) {
        $resolvedDestList += "C:\BKP_SISMOTEL"
    }
}
foreach ($d in $resolvedDestList) {
    if (-not $d.StartsWith("\\") -and -not (Test-Path $d)) {
        try { New-Item -ItemType Directory -Path $d -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
    }
}

$tempDir = $null
$dbDrive = [System.IO.Path]::GetPathRoot($dbPath)

# Exige espaco para o FBK + GZ (1.5x o banco) mais a reserva do disco
# (Get-ProcessingRequiredMB): 5 GB, ou max(5 GB, 10%) no disco do banco.
$minRequiredMB = [math]::Round($dbSizeMB * 1.5 + $script:MinFreeDiskMB, 2)

# 1) Procura um destino local em particao diferente do banco para isolamento fisico de gravacao
foreach ($candDest in $resolvedDestList) {
    if ($candDest.StartsWith("\")) { continue } # NUNCA usar rede para temporario
    $candDrive = [System.IO.Path]::GetPathRoot($candDest)
    if ((Test-Path $candDrive) -and ($candDrive -ne $dbDrive)) {
        if ((Get-DriveFreeMB -Path $candDrive) -ge (Get-ProcessingRequiredMB -Path $candDrive -DbDrive $dbDrive -DbSizeMB $dbSizeMB -Factor 1.5)) {
            $candidateTemp = Join-Path $candDrive "FIBS_TEMP"
            try {
                if (-not (Test-Path $candidateTemp)) { New-Item -ItemType Directory -Path $candidateTemp -Force | Out-Null }
                try {
                    $attr = [System.IO.File]::GetAttributes($candidateTemp)
                    if (($attr -band [System.IO.FileAttributes]::Hidden) -ne [System.IO.FileAttributes]::Hidden) {
                        [System.IO.File]::SetAttributes($candidateTemp, $attr -bor [System.IO.FileAttributes]::Hidden)
                    }
                } catch {}
                $tempDir = $candidateTemp
                break
            } catch {}
        }
    }
}

# 2) Nenhum destino isolado com espaco. Tenta qualquer outro destino local disponivel.
if ($null -eq $tempDir) {
    foreach ($candDest in $resolvedDestList) {
        if ($candDest.StartsWith("\")) { continue }
        $candDrive = [System.IO.Path]::GetPathRoot($candDest)
        if (Test-Path $candDrive) {
            if ((Get-DriveFreeMB -Path $candDrive) -ge (Get-ProcessingRequiredMB -Path $candDrive -DbDrive $dbDrive -DbSizeMB $dbSizeMB -Factor 1.5)) {
                $candidateTemp = Join-Path $candDrive "FIBS_TEMP"
                try {
                    if (-not (Test-Path $candidateTemp)) { New-Item -ItemType Directory -Path $candidateTemp -Force | Out-Null }
                    try {
                        $attr = [System.IO.File]::GetAttributes($candidateTemp)
                        if (($attr -band [System.IO.FileAttributes]::Hidden) -ne [System.IO.FileAttributes]::Hidden) {
                            [System.IO.File]::SetAttributes($candidateTemp, $attr -bor [System.IO.FileAttributes]::Hidden)
                        }
                    } catch {}
                    $tempDir = $candidateTemp
                    break
                } catch {}
            }
        }
    }
}

# 3) Fallback final: a propria pasta do script FIBS
if ($null -eq $tempDir) {
    $fallbackTemp = Join-Path $scriptDir "temp_backup"
    if ((Get-DriveFreeMB -Path $fallbackTemp) -ge (Get-ProcessingRequiredMB -Path $fallbackTemp -DbDrive $dbDrive -DbSizeMB $dbSizeMB -Factor 1.5)) {
        try {
            if (-not (Test-Path $fallbackTemp)) { New-Item -ItemType Directory -Path $fallbackTemp -Force | Out-Null }
            $tempDir = $fallbackTemp
        } catch {}
    }
}

if ($null -eq $tempDir) {
    # Nenhuma unidade possui espaco suficiente!
    $errMsg = "ALERTA PREVENTIVO DE SEGURANCA: Nenhuma unidade possui os $minRequiredMB MB livres necessarios (1.5x o banco + reserva minima de $($script:MinFreeDiskMB) MB livres; no disco do banco a reserva e max(5 GB, 10%)). Para proteger o banco Firebird e o sistema contra corrupcao por falta de espaco em disco, a rotina foi interrompida preventivamente com 100% de seguranca."
    Log-Message $errMsg
    Send-BackupNotification -Status "FALHA" -SubjectInfo "Espaco em Disco Critico ($TaskName)" -BodyDetails $errMsg -DbPath $dbPath -DbSize "$dbSizeMB"
    Exit-BackupLock
    exit 1
}

Log-Message "Diretorio temporario de processamento I/O: $tempDir"

# Sobras de rotinas interrompidas (queda de energia, gbak abortado) ocupariam o disco
# para sempre dentro de uma pasta oculta. Com a trava em maos, e seguro limpar.
$pastasTemp = @($tempDir, (Join-Path $scriptDir "temp_backup"))
foreach ($candDest in $resolvedDestList) {
    if (-not $candDest.StartsWith("\")) {
        $pastasTemp += (Join-Path ([System.IO.Path]::GetPathRoot($candDest)) "FIBS_TEMP")
    }
}
Clear-StaleBackupTemp -Directories $pastasTemp

try {
    $tempRoot = [System.IO.Path]::GetPathRoot($tempDir)
    $freeSpaceMB = Get-DriveFreeMB -Path $tempRoot
    $minRequiredMB = Get-ProcessingRequiredMB -Path $tempRoot -DbDrive $dbDrive -DbSizeMB $dbSizeMB -Factor 1.5
    Log-Message "Espaco livre na unidade de processamento ($tempRoot): $freeSpaceMB MB (Minimo seguro exigido: $minRequiredMB MB)"
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
                $r = Invoke-ExternalTool -FilePath $gfixPath -Arguments "-sweep `"localhost:$dbPath`"" -Environment $fbEnv -TimeoutMs 300000
                if ($r.TimedOut) {
                    Log-Message "Aviso: gfix -sweep atingiu timeout de 5 minutos."
                } elseif ($r.ExitCode -eq 0) {
                    Log-Message "gfix -sweep concluido com sucesso."
                } else {
                    Log-Message "Aviso: gfix -sweep retornou codigo $($r.ExitCode): $($r.StdErr)$($r.StdOut)"
                }
            } catch {
                Log-Message "Aviso ao rodar gfix sweep: $_"
            }
        }

        if ($runGfixValidate) {
            Log-Message "Executando gfix.exe (-v) para verificacao de integridade..."
            try {
                $r = Invoke-ExternalTool -FilePath $gfixPath -Arguments "-v `"localhost:$dbPath`"" -Environment $fbEnv -TimeoutMs 300000
                if ($r.TimedOut) {
                    Log-Message "Aviso: gfix validacao atingiu timeout."
                } elseif ($r.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace("$($r.StdErr)$($r.StdOut)")) {
                    Log-Message "gfix -v validacao concluida sem erros."
                } else {
                    Log-Message "Aviso: gfix validacao reportou possiveis anomalias (codigo $($r.ExitCode)): $($r.StdErr)$($r.StdOut)"
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
$tempGz    = Join-Path $tempDir "$basePrefix-$seqStr.GZ"
$gbakLog    = Join-Path $tempDir "gbak_$($TaskName)_log.txt"

# Argumentos GBAK: -b (backup online), -t (transportavel), -g (SEM coleta de lixo / nao trava tabelas ativas)
# Usuario/senha vao por ISC_USER/ISC_PASSWORD (variaveis de ambiente do processo
# filho), nunca na linha de comando.
$gbakArgs = "-b -t"
if ($noGarbageCollection) { $gbakArgs += " -g" }
if ($convertExternal)    { $gbakArgs += " -co" }
$gbakArgs += " -y `"$gbakLog`""
$gbakArgs += " `"localhost:$dbPath`" `"$tempFbk`""

$global:gbakTimer.Restart()
Log-Message "Executando gbak.exe (Backup Online Seguro em Prioridade Baixa)..."

$gbakSuccess = $false
$gbakError = ""
for ($attempt = 1; $attempt -le $retryCount; $attempt++) {
    try {
        if (Test-Path $tempFbk) { Remove-Item $tempFbk -Force -ErrorAction SilentlyContinue }
        if (Test-Path $gbakLog) { Remove-Item $gbakLog -Force -ErrorAction SilentlyContinue }

        # Timeout de 2 horas (7200000 ms)
        $r = Invoke-ExternalTool -FilePath $gbakPath -Arguments $gbakArgs -Environment $fbEnv -TimeoutMs 7200000
        if ($r.TimedOut) {
            $gbakError = "gbak excedeu o limite de 2 horas e foi finalizado."
            Log-Message "Tentativa $attempt falhou: $gbakError"
        } elseif ($r.ExitCode -eq 0 -and (Test-Path $tempFbk)) {
            $gbakSuccess = $true
            $global:gbakTimer.Stop()
            $fbkSizeMB = [math]::Round(((Get-Item $tempFbk).Length / 1MB), 2)
            $gbakElapsedStr = Format-DurationText $global:gbakTimer.Elapsed
            Log-Message "gbak.exe concluido com sucesso! Arquivo FBK gerado ($fbkSizeMB MB) em $gbakElapsedStr."
            break
        } else {
            $gbakError = "$($r.StdErr)".Trim()
            if (Test-Path $gbakLog) { $gbakError = ((Get-Content $gbakLog -Tail 5) -join "`n") + "`n" + $gbakError }
            if ([string]::IsNullOrWhiteSpace($gbakError)) { $gbakError = "Sem detalhes no log." }
            Log-Message "Tentativa $attempt falhou. Codigo: $($r.ExitCode). Erro: $gbakError"
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
    # FBK parcial (gbak abortado/morto) nao pode ficar ocupando o disco
    if (Test-Path $tempFbk) { Remove-Item $tempFbk -Force -ErrorAction SilentlyContinue }
    if (Test-Path $gbakLog) { Remove-Item $gbakLog -Force -ErrorAction SilentlyContinue }
    Send-BackupNotification -Status "FALHA" -SubjectInfo "Falha no GBAK ($TaskName)" -BodyDetails $errMsg -DbPath $dbPath -DbSize "$dbSizeMB"

    # Se a tarefa for externa, avaliar e alertar se a contingencia externa esta atrasada
    $isExternalTask = ($TaskName -match "EXTERN" -or $TaskName -eq "BKP_EXTERNO")
    if ($isExternalTask) {
        Test-ExternalDestinationsHealth -TaskName $TaskName -Destinations $resolvedDestList -FailureReason "Falha no gbak.exe (Erro no banco de dados Firebird)" -AllowDisconnect
    }
    Exit-BackupLock
    exit 1
}

# --- FASE 4: COMPACTACAO DIRETA FBK -> GZ (PRIORIDADE BAIXA) ---
$global:zipTimer.Restart()

# Impressao digital do .fbk ANTES de compactar. E contra ela que o GZ sera conferido,
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
    Exit-BackupLock
    exit 1
}
Log-Message "Origem: $fbkEntryName | $([math]::Round($fbkSizeBytes/1MB,2)) MB | SHA-256 $($fbkSha.Substring(0,16))..."

Log-Message "Compactando backup para arquivo .GZ (Compressao Maxima em Prioridade Baixa)..."
$gzSizeMB = 0
$zipSha = $null
try {
    if (Test-Path $tempGz) { Remove-Item $tempGz -Force -ErrorAction SilentlyContinue }
    
    $compressionSuccess = $false
    try {
        try {
            Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
            Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
        } catch {
            [System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression") | Out-Null
            [System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null
        }
        
        $zip = [System.IO.Compression.ZipFile]::Open($tempGz, [System.IO.Compression.ZipArchiveMode]::Create)
        $entryName = Split-Path $tempFbk -Leaf
        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $tempFbk, $entryName, [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
        $zip.Dispose()
        $compressionSuccess = $true
    } catch {
        Log-Message "Aviso: API de compactacao nativa falhou. Usando fallback Compress-Archive..."
        if (Test-Path $tempGz) { Remove-Item $tempGz -Force -ErrorAction SilentlyContinue }
        Compress-Archive -Path $tempFbk -DestinationPath $tempGz -CompressionLevel Optimal -Force -ErrorAction Stop
        $compressionSuccess = $true
    }

    if ($compressionSuccess -and (Test-Path $tempGz) -and ((Get-Item $tempGz).Length -gt 0)) {
        $gzSizeMB = [math]::Round(((Get-Item $tempGz).Length / 1MB), 2)

        # PORTAO DE INTEGRIDADE: le o GZ de volta e confere o conteudo contra o .fbk.
        # So passando daqui o .fbk original pode ser descartado.
        Log-Message "Verificando integridade do GZ gerado (releitura + SHA-256)..."
        $verif = Test-BackupGzIntegrity -GzPath $tempGz -ExpectedEntryName $fbkEntryName -ExpectedSize $fbkSizeBytes -ExpectedSha256 $fbkSha
        if (-not $verif.Ok) {
            throw "GZ GERADO ESTA CORROMPIDO. $($verif.Reason)"
        }
        Log-Message "Integridade do GZ CONFIRMADA: $($verif.Reason)"

        # Impressao digital do proprio GZ, usada para conferir cada copia nos destinos
        $zipSha = Get-Sha256OfFile -Path $tempGz
        if ([string]::IsNullOrWhiteSpace($zipSha)) { throw "Nao foi possivel calcular o SHA-256 do GZ verificado." }

        $global:zipTimer.Stop()
        $zipElapsedStr = Format-DurationText $global:zipTimer.Elapsed
        Log-Message "Arquivo GZ gerado e verificado: $tempGz ($gzSizeMB MB) em $zipElapsedStr | SHA-256 $($zipSha.Substring(0,16))..."

        # Agora sim e seguro remover o FBK bruto para poupar espaco em disco
        Remove-Item $tempFbk -Force -ErrorAction SilentlyContinue
    } else {
        throw "Arquivo GZ nao foi gerado corretamente ou esta vazio."
    }
} catch {
    $errMsg = "ERRO na compactacao do GZ: $_"
    Log-Message $errMsg
    Send-BackupNotification -Status "FALHA" -SubjectInfo "Falha na Compactacao ($TaskName)" -BodyDetails $errMsg -DbPath $dbPath -DbSize "$dbSizeMB"
    if (Test-Path $tempFbk) { Remove-Item $tempFbk -Force -ErrorAction SilentlyContinue }
    if (Test-Path $tempGz) { Remove-Item $tempGz -Force -ErrorAction SilentlyContinue }
    Exit-BackupLock
    exit 1
}

# --- FASE 5: DISTRIBUICAO PARA DESTINOS E EXPURGO AUTOMATICO ---
$fileName = Split-Path $tempGz -Leaf
$localSuccessList = @()
$networkSuccessList = @()
$failedDestinations = @($missingLocalDests)
$destinationFailureReasons = @{}
# Todos os destinos configurados da tarefa (ja traduzidos para UNC quando mapeados)
$allDestinations = @($resolvedDestList) + @($missingLocalDests)

foreach ($destTrimmed in $resolvedDestList) {
    # Motivo de falha pertence somente a este destino. Nunca reutilizar uma falha
    # de autenticacao para decidir se o proximo UNC deve ou nao ser tentado.
    $destinationFailureReason = ""
    $isNetwork = $destTrimmed.StartsWith("\\")
    $destTypeTag = if ($isNetwork) { "[REDE UNC]" } else { "[LOCAL]" }
    $finalPath = $null
    Log-Message "Gravando backup GZ no destino $($destTypeTag) - $destTrimmed"

    $destSuccess = $false
    for ($attempt = 1; $attempt -le $retryCount; $attempt++) {
        try {


            # Normalizacao e limpeza do caminho de destino
            $destClean = $destTrimmed.Trim().Trim('"', "'").TrimEnd('\', '/')
            $fileNameClean = (Split-Path $tempGz -Leaf).Trim().Trim('"', "'")
            $finalPath = "$destClean\$fileNameClean"

            # Cria a pasta caso nao exista (com protecao contra "The path is not of a legal form" em compartilhamento UNC)
            if (-not $isNetwork) {
                if (-not (Test-Path $destClean)) {
                    [System.IO.Directory]::CreateDirectory($destClean) | Out-Null
                }
            } else {
                $uncParts = $destClean.TrimStart('\').Split('\')
                if ($uncParts.Length -le 2) {
                    # Trata-se de \\servidor\compartilhamento raiz
                    if (-not (Test-Path $destClean)) {
                        throw "O compartilhamento de rede '$destClean' esta inacessivel ou nao existe no servidor remoto."
                    }
                } else {
                    # Trata-se de \\servidor\compartilhamento\subpasta ou \\servidor\c$\subpasta
                    $uncRoot = "\\$($uncParts[0])\$($uncParts[1])"
                    if (-not (Test-Path $uncRoot)) {
                        throw "O compartilhamento base '$uncRoot' esta inacessivel ou nao existe no servidor remoto."
                    }
                    if (-not (Test-Path $destClean)) {
                        try {
                            [System.IO.Directory]::CreateDirectory($destClean) | Out-Null
                        } catch {
                            throw "Nao foi possivel criar a subpasta em '$destClean': $_"
                        }
                    }
                }
            }

            # PROTECAO DE DISCO: abre espaco (remove os backups mais antigos do prefixo,
            # preservando os 3 mais recentes) ou desiste da copia, sem nunca zerar o disco.
            $srcLen = (Get-Item $tempGz).Length
            if (-not $isNetwork) {
                $destIsDbDrive = ([System.IO.Path]::GetPathRoot($destClean) -eq $dbDrive)
                $guard = Invoke-DestinationSpaceGuard -Directory $destClean -Prefix $basePrefix -IncomingMB ($srcLen / 1MB) -IsDbDrive $destIsDbDrive
                if (-not $guard.Ok) {
                    $destinationFailureReason = $guard.Message
                    Log-Message "PROTECAO DE DISCO: $($guard.Message)"
                    break
                }
            }

            # Copia o arquivo .GZ para o destino
            Copy-Item -Path $tempGz -Destination $finalPath -Force -ErrorAction Stop

            if (-not (Test-Path $finalPath)) { throw "Arquivo de destino nao foi gravado." }

            # CONFERENCIA DA COPIA: tamanho e SHA-256 contra o GZ de origem ja verificado.
            # Uma copia truncada ou com bits trocados (queda de rede, disco com defeito)
            # tem tamanho > 0 e passaria na checagem antiga; aqui ela e reprovada e a
            # tentativa e refeita, sem nunca chegar na politica de retencao.
            $destLen = (Get-Item $finalPath).Length
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

            $destSuccess = $true
            if ($isNetwork) {
                $networkSuccessList += $finalPath
            } else {
                $localSuccessList += $finalPath
            }
            Log-Message "Backup GZ gravado e CONFERIDO em: $finalPath (SHA-256 identico a origem)"

            # Politica de Retencao (Expurgo dos mais antigos por tarefa / prefixo)
            Invoke-RetentionPolicy -Directory $destClean -Prefix $basePrefix -Keep $keepBackupsCount
            break
        } catch {
            Log-Message "Tentativa $attempt de copia para '$destTrimmed' falhou: $_"
            if ([string]::IsNullOrWhiteSpace($destinationFailureReason)) { $destinationFailureReason = "$_" }
            # Servico sem permissao na pasta de rede: repetir nao adianta; vai direto para
            # a copia pelo usuario logado (logo abaixo).
            $semPermissao = ($isNetwork -and (Test-IsSystemAccount) -and (Test-IsAccessDeniedError $_))
            # Nao deixar arquivo reprovado na pasta: ele seria contado como "backup
            # existente" pelo monitor e pela numeracao sequencial, mascarando a falha.
            try {
                if (-not [string]::IsNullOrWhiteSpace($finalPath) -and (Test-Path $finalPath)) {
                    Remove-Item $finalPath -Force -ErrorAction SilentlyContinue
                    Log-Message "Copia reprovada removida do destino para nao mascarar a falha: $finalPath"
                }
            } catch {}
            if ($semPermissao) { break }
        }

        if ($attempt -lt $retryCount) {
            Start-Sleep -Seconds $retryInterval
        }
    }

    # O servico nao conseguiu gravar na pasta de rede: a copia e feita pelo usuario logado
    # no servidor, com o mesmo acesso do Explorer (como o FIBS original fazia).
    if (-not $destSuccess -and $isNetwork -and (Test-IsSystemAccount)) {
        Log-Message "Rede: o servico nao gravou em '$destTrimmed'. Copiando pelo usuario logado no servidor..."
        $viaUser = Copy-ViaLoggedOnUser -DestDir ($destTrimmed.Trim().TrimEnd('\', '/')) -SourceFile $tempGz -Prefix $basePrefix -Keep $keepBackupsCount -ExpectedSha $zipSha
        if ($viaUser.Ok) {
            $destSuccess = $true
            $networkSuccessList += $viaUser.FinalPath
            Log-Message "Backup GZ gravado e CONFERIDO em: $($viaUser.FinalPath) pelo usuario logado $($viaUser.User) (SHA-256 identico a origem; $($viaUser.Removed) backup(s) antigo(s) removido(s) pela retencao)"
        } else {
            $destinationFailureReason = "o servico nao tem permissao na pasta e a copia pelo usuario logado falhou: $($viaUser.Message)"
            Log-Message "AVISO DE REDE: '$destTrimmed': $destinationFailureReason"
        }
    }

    if (-not $destSuccess) {
        if (-not [string]::IsNullOrWhiteSpace($destinationFailureReason)) {
            $destinationFailureReasons[$destTrimmed] = $destinationFailureReason
        }
        if (-not ($failedDestinations -contains $destTrimmed)) {
            $failedDestinations += $destTrimmed
        }
        if ($isNetwork) {
            Log-Message "AVISO DE REDE: O computador remoto '$destTrimmed' esta inacessivel (equipamento offline, desligado ou sem permissao). O backup local permanece 100% seguro."
        } else {
            Log-Message "ERRO: Falha definitiva de copia para o destino local: $destTrimmed"
        }
    }
}

# GARANTIA DE FAIL-SAFE LOCAL: Se nenhum destino foi gravado, grava uma copia de ultima
# linha no servidor -- COM retencao e SEM encher o disco do banco de dados.
if ($localSuccessList.Count -eq 0 -and $networkSuccessList.Count -eq 0) {
    $localSafeDir = Select-FailSafeDirectory -DbPath $dbPath -GzSizeMB $gzSizeMB
    if ($null -eq $localSafeDir) {
        Log-Message "ESCUDO FAIL-SAFE: nenhum disco local tem folga segura para a copia de ultima linha. Copia nao gravada para proteger o Firebird."
    } else {
        Log-Message "ESCUDO FAIL-SAFE ATIVADO: Todos os destinos configurados falharam ou estao indisponiveis. Gravando copia de seguranca de ultima linha no servidor local em: $localSafeDir"
        try {
            if (-not (Test-Path $localSafeDir)) { New-Item -ItemType Directory -Path $localSafeDir -Force -ErrorAction Stop | Out-Null }
            $safeFinalPath = Join-Path $localSafeDir $fileName
            Copy-Item -Path $tempGz -Destination $safeFinalPath -Force -ErrorAction Stop
            if (Test-Path $safeFinalPath) {
                # A copia de ultima linha tambem passa pela conferencia: e justamente a que
                # sera usada num desastre, entao nao pode ser aceita sem verificacao.
                $safeSha = Get-Sha256OfFile -Path $safeFinalPath
                if ($safeSha -eq $zipSha) {
                    $localSuccessList += $safeFinalPath
                    Log-Message "Copia de seguranca local gravada e CONFERIDA em: $safeFinalPath"
                    Invoke-RetentionPolicy -Directory $localSafeDir -Prefix $basePrefix -Keep $keepBackupsCount
                } else {
                    Log-Message "ERRO: a copia fail-safe em '$safeFinalPath' nao confere com a origem (SHA-256 divergente). Arquivo descartado."
                    Remove-Item $safeFinalPath -Force -ErrorAction SilentlyContinue
                }
            }
        } catch {
            Log-Message "Aviso no escudo fail-safe local: $_"
        }
    }
}

# --- FASE 6: LIMPEZA FINAL DE ARQUIVOS TEMPORARIOS ---
# A trava de backup so e liberada no FIM (depois do monitor de destinos, e-mails e
# LiveUpdate): antes ela era liberada aqui e essas etapas corriam em paralelo com a
# rotina seguinte.
if (Test-Path $tempGz) { Remove-Item $tempGz -Force -ErrorAction SilentlyContinue }
if (Test-Path $gbakLog) { Remove-Item $gbakLog -Force -ErrorAction SilentlyContinue }

if ($global:routineTimer.IsRunning) { $global:routineTimer.Stop() }
$durationStr = Format-DurationText $global:routineTimer.Elapsed
$gbakDurationStr = if ($global:gbakTimer.ElapsedMilliseconds -gt 0) { Format-DurationText $global:gbakTimer.Elapsed } else { "N/A" }
$zipDurationStr = if ($global:zipTimer.ElapsedMilliseconds -gt 0) { Format-DurationText $global:zipTimer.Elapsed } else { "N/A" }

$compRatio = ""
if ($dbSizeMB -gt 0 -and $gzSizeMB -gt 0) {
    $pct = [Math]::Round((1.0 - ([double]$gzSizeMB / [double]$dbSizeMB)) * 100, 1)
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
    $isNetTask = ($TaskName -match "EXTERN" -or @($allDestinations | Where-Object { $_ -match '^\\\\' }).Count -gt 0)
    if ($isNetTask) {
        $subjectInfo = "Destino Externo Offline / Inacessivel ($TaskName)"
        $errMsg = @"
AVISO DE CONECTIVIDADE / REDE EXTERNA:
O backup do banco de dados foi extraido e compactado com 100% DE SUCESSO no servidor, porem nao foi possivel copiar para o computador de destino na rede ($($failedDestinations -join ', ')) nem gravar a copia de ultima linha no servidor.

Causas mais frequentes para verificar:
1. Computador da Recepcao/Terminal desligado, hibernando ou fora da tomada/rede;
2. Pasta descompartilhada, renomeada ou sem permissao no computador remoto;
3. Pasta sem permissao de gravacao para o servidor nas abas Compartilhamento e Seguranca (teste pelo botao 'Testar Acesso como SYSTEM');
4. Cabo de rede desconectado, oscilacao de Wi-Fi ou IP do terminal alterado;
5. Discos locais do servidor sem espaco livre para a copia de seguranca.
"@
    } else {
        $subjectInfo = "Falha ao Gravar nos Discos Locais ($TaskName)"
        $errMsg = "ERRO CRITICO: Nao foi possivel gravar nos discos locais do servidor ($($failedDestinations -join ', ')). Verifique se as unidades locais estao cheias ou sem permissao de gravacao."
    }
    Log-Message $errMsg
    Send-BackupNotification -Status "FALHA" -SubjectInfo $subjectInfo -BodyDetails $errMsg -ZipFile $fileName -ZipSize "$gzSizeMB" -FbkSize "$fbkSizeMB" -DbPath $dbPath -DbSize "$dbSizeMB" -DurationStr $durationStr -GbakDurationStr $gbakDurationStr -ZipDurationStr $zipDurationStr -CompressionRatio $compRatio -FreeSpaceInfo $diskInfo
    if ($TaskName -match "EXTERN" -or $isNetTask) {
        foreach ($destToCheck in $failedDestinations) {
            $motivo = if ($destinationFailureReasons.ContainsKey($destToCheck)) { $destinationFailureReasons[$destToCheck] } else { $networkConfigFailureReason }
            Test-ExternalDestinationsHealth -TaskName $TaskName -Destinations @($destToCheck) -FailureReason $motivo -AllowDisconnect
        }
    }
    # CAMADA AUTO-UPDATE RESILIENTE: Mesmo com falha nos destinos, verifica atualizacao na nuvem
    # para que o cliente receba correcoes e melhorias sem ficar travado em versoes antigas.
    try {
        Invoke-MecLiveUpdate -Force:$ForceUpdate
    } catch {
        Log-Message "Aviso na verificacao de auto-update: $_"
    }
    Exit-BackupLock
    exit 1
}

# Numero de sequencia consumido apenas quando ha backup gravado
Save-BackupSequenceNumber -Prefix $basePrefix -UsedNumber $seqNumber -SequenceFilePath $seqFile

$allSuccessList = $localSuccessList + $networkSuccessList
if ($failedDestinations.Count -gt 0) {
    Log-Message "Rotina de backup concluida PARCIALMENTE ($($allSuccessList.Count) destino(s) gravado(s), $($failedDestinations.Count) falho(s)/pendente(s): $($failedDestinations -join ', '))."
} else {
    Log-Message "Rotina de backup concluida com SUCESSO! ($($allSuccessList.Count) destino(s) gravado(s))."
}

# Carimba a conclusao para a guarda anti-duplicidade da proxima invocacao e para o
# servico/startup guard decidirem se falta backup apos um reboot.
# Gravado apenas em caso de sucesso: se a rotina falhar, um novo disparo deve poder tentar.
try {
    Invoke-WithMecLock -Name "State" -Script {
        $runs = @{}
        if (Test-Path $lastRunFile) {
            $prevRuns = Get-Content $lastRunFile -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($null -ne $prevRuns) {
                foreach ($prop in $prevRuns.psobject.Properties) { $runs[$prop.Name] = "$($prop.Value)" }
            }
        }
        $runs[$TaskName] = (Get-Date).ToString("o")
        Save-JsonState -Path $lastRunFile -Data $runs
    }
} catch {
    Log-Message "Aviso ao registrar a conclusao da tarefa: $_"
}

$bodyReport = @"
Relatorio de Execucao da Rotina:
Status: $(if ($failedDestinations.Count -gt 0) { 'PARCIALMENTE CONCLUIDO (DESTINOS PENDENTES)' } else { 'SUCESSO COMPLETO' })
Tarefa: $TaskName
Computador / Servidor: $env:COMPUTERNAME
Arquivo Gerado: $fileName
Tamanho Compactado: $gzSizeMB MB
Banco Original: $dbPath ($dbSizeMB MB)

Destinos Gravados com Sucesso:
$($allSuccessList -join "`r`n")
"@

# Rastreamento e Monitoramento Continuo de Destinos (Watchdog 24h)
$netTracker = @{}
$trackerKeys = @()
foreach ($successPath in ($networkSuccessList + $localSuccessList)) {
    $destDir = Split-Path $successPath -Parent
    $netTracker[$destDir] = @{ LastSuccess = (Get-Date).ToString("o"); FirstFailure = $null; LastAlert = $null }
    $trackerKeys += $destDir
}
if ($trackerKeys.Count -gt 0) {
    # Preserva o historico existente dos demais destinos; so estes sao renovados
    Save-NetworkTrackerEntries -Entries $netTracker -Keys $trackerKeys
}

# Verificacao Blindada de Saude de Destinos Externos / Rede (24 Horas)
$isExternalTask = ($TaskName -match "EXTERN" -or $TaskName -eq "BKP_EXTERNO")
if ($failedDestinations.Count -gt 0 -or $isExternalTask) {
    $destsToCheck = if ($failedDestinations.Count -gt 0) { $failedDestinations } else { $allDestinations }
    foreach ($destToCheck in $destsToCheck) {
        $failureReasonForDestination = $networkConfigFailureReason
        if ($destinationFailureReasons.ContainsKey($destToCheck)) {
            $failureReasonForDestination = $destinationFailureReasons[$destToCheck]
        }
        Test-ExternalDestinationsHealth -TaskName $TaskName -Destinations @($destToCheck) -FailureReason $failureReasonForDestination -AllowDisconnect
    }
}

if ($failedDestinations.Count -gt 0) {
    $bodyReport += @"

Avisos de Destinos Nao Sincronizados / Com Falha:
$($failedDestinations -join "`r`n")
(Observacao: O backup local no servidor foi concluido com 100% de integridade. Verifique se os computadores da rede acima estao ligados ou se as unidades existem.)
"@
    Send-BackupNotification -Status "SUCESSO" -SubjectInfo "Backup $TaskName Concluido Parcialmente ($gzSizeMB MB) [Alerta Destino]" -BodyDetails $bodyReport -ZipFile $fileName -ZipSize "$gzSizeMB" -FbkSize "$fbkSizeMB" -DbPath $dbPath -DbSize "$dbSizeMB" -DurationStr $durationStr -GbakDurationStr $gbakDurationStr -ZipDurationStr $zipDurationStr -CompressionRatio $compRatio -FreeSpaceInfo $diskInfo -SuccessDests $allSuccessList -WarningDests $failedDestinations
} else {
    Send-BackupNotification -Status "SUCESSO" -SubjectInfo "Backup $TaskName Concluido com Sucesso ($gzSizeMB MB)" -BodyDetails $bodyReport -ZipFile $fileName -ZipSize "$gzSizeMB" -FbkSize "$fbkSizeMB" -DbPath $dbPath -DbSize "$dbSizeMB" -DurationStr $durationStr -GbakDurationStr $gbakDurationStr -ZipDurationStr $zipDurationStr -CompressionRatio $compRatio -FreeSpaceInfo $diskInfo -SuccessDests $allSuccessList -WarningDests @()
}

# A auditoria diaria NAO roda mais dentro da rotina de backup: ela e disparada so
# pelo servico (03:30, -RunAuditOnly -ScheduledAudit) com trava propria. Rodar nos
# dois lugares gerava duas auditorias no mesmo dia disputando a mesma sandbox.

# CAMADA AUTO-UPDATE EM NUVEM (MEC LiveUpdate assinado)
try {
    Invoke-MecLiveUpdate -Force:$ForceUpdate
} catch {
    Log-Message "Aviso na verificacao de auto-update: $_"
}

Exit-BackupLock
Log-Message "======================================================"
exit 0
