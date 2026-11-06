# ============================================
# DeepSeek Block Proxy на TcpListener
# Работает БЕЗ прав администратора
# Слушает 127.0.0.1:8080
# ============================================

$ListenPort = 8080
$BlockedDomains = @(
    "mail.google.com",
    "qwen.ai",
    "chat.qwen.ai",
    "z.ai",
    "chat.z.ai",
    "deepseek.com",
    "chat.deepseek.com",
    "api.deepseek.com",
    "platform.deepseek.com",
    "resources.deepseek.com",
    "cdn.deepseek.com"
)

function Test-BlockedHost {
    param([string]$Host)
    if ([string]::IsNullOrWhiteSpace($Host)) { return $false }
    $Host = $Host.ToLower().Trim()
    foreach ($domain in $BlockedDomains) {
        if ($Host -eq $domain -or $Host.EndsWith(".$domain")) {
            return $true
        }
    }
    return $false
}

function Send-HttpResponse {
    param($Stream, [int]$StatusCode, [string]$StatusText, [string]$Body, [string]$ContentType = "text/html; charset=utf-8")
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
    $header = "HTTP/1.1 $StatusCode $StatusText`r`n" +
              "Content-Type: $ContentType`r`n" +
              "Content-Length: $($bodyBytes.Length)`r`n" +
              "Connection: close`r`n" +
              "Proxy-Connection: close`r`n`r`n"
    $headerBytes = [System.Text.Encoding]::ASCII.GetBytes($header)
    $Stream.Write($headerBytes, 0, $headerBytes.Length)
    $Stream.Write($bodyBytes, 0, $bodyBytes.Length)
    $Stream.Flush()
}

$tcpListener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $ListenPort)
try {
    $tcpListener.Start()
} catch {
    Write-Host "[!] Не удалось занять порт $ListenPort : $_" -ForegroundColor Red
    exit 1
}

Write-Host "[+] DeepSeek Block Proxy запущен на 127.0.0.1:$ListenPort" -ForegroundColor Green
Write-Host "[+] Блокируемые домены:" -ForegroundColor Yellow
$BlockedDomains | ForEach-Object { Write-Host "    - $_" -ForegroundColor Yellow }
Write-Host "[+] Ctrl+C для остановки" -ForegroundColor Gray

function Handle-Client {
    param($Client)
    try {
        $stream = $Client.GetStream()
        $stream.ReadTimeout = 5000

        # Читаем первую строку запроса
        $buffer = New-Object byte[] 4096
        $read = $stream.Read($buffer, 0, $buffer.Length)
        if ($read -eq 0) { $Client.Close(); return }

        $requestText = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $read)
        $firstLine = ($requestText -split "`r`n")[0]
        $parts = $firstLine -split " "
        if ($parts.Length -lt 2) { $Client.Close(); return }

        $method = $parts[0]
        $target = $parts[1]

        # --- CONNECT (HTTPS-туннель) ---
        if ($method -eq "CONNECT") {
            $targetHost = ($target -split ":")[0]
            if (Test-BlockedHost $targetHost) {
                Write-Host "[BLOCKED-CONNECT] $targetHost" -ForegroundColor Red
                Send-HttpResponse -Stream $stream -StatusCode 403 -StatusText "Forbidden" -Body "DeepSeek blocked"
            } else {
                # Пробрасываем туннель
                try {
                    $remoteParts = $target -split ":"
                    $remoteHost = $remoteParts[0]
                    $remotePort = if ($remoteParts[1]) { [int]$remoteParts[1] } else { 443 }
                    $remoteTcp = New-Object System.Net.Sockets.TcpClient($remoteHost, $remotePort)
                    $remoteStream = $remoteTcp.GetStream()

                    $ok = [System.Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 Connection Established`r`n`r`n")
                    $stream.Write($ok, 0, $ok.Length)
                    $stream.Flush()

                    # Двусторонний проброс
                    $task1 = $stream.CopyToAsync($remoteStream)
                    $task2 = $remoteStream.CopyToAsync($stream)
                    [System.Threading.Tasks.Task]::WaitAny($task1, $task2)
                    $remoteTcp.Close()
                } catch {
                    Write-Host "[ERROR-CONNECT] $target : $_" -ForegroundColor DarkYellow
                }
            }
            $Client.Close()
            return
        }

        # --- Обычный HTTP ---
        $targetHost = ""
        if ($target -match "^https?://([^/:]+)") {
            $targetHost = $Matches[1]
        } else {
            # Ищем Host: в заголовках
            if ($requestText -match "(?m)^Host:\s*([^:\r\n]+)") {
                $targetHost = $Matches[1]
            }
        }

        if (Test-BlockedHost $targetHost) {
            Write-Host "[BLOCKED-HTTP] $targetHost" -ForegroundColor Red
            $html = "<html><body style='font-family:sans-serif;text-align:center;padding:50px'><h1>⛔ Доступ заблокирован</h1><p>DeepSeek заблокирован локальной политикой.</p></body></html>"
            Send-HttpResponse -Stream $stream -StatusCode 403 -StatusText "Forbidden" -Body $html
            $Client.Close()
            return
        }

        # Проксируем разрешённый HTTP-запрос
        try {
            $webReq = [System.Net.WebRequest]::Create($target)
            $webReq.Method = $method
            $webReq.AllowAutoRedirect = $false
            # Пересылаем заголовки
            foreach ($line in ($requestText -split "`r`n")) {
                if ($line -match "^([^:]+):\s*(.+)$") {
                    $hName = $Matches[1].Trim()
                    $hVal  = $Matches[2].Trim()
                    if ($hName -eq "Host") { $webReq.Host = $hVal }
                    elseif ($hName -eq "User-Agent") { $webReq.UserAgent = $hVal }
                    elseif ($hName -eq "Accept") { try { $webReq.Accept = $hVal } catch {} }
                }
            }
            $webResp = $webReq.GetResponse()
            $respStream = $webResp.GetResponseStream()
            $respStream.CopyTo($stream)
            $webResp.Close()
        } catch {
            Write-Host "[ERROR-HTTP] $target : $_" -ForegroundColor DarkYellow
        }
        $Client.Close()
    } catch {
        try { $Client.Close() } catch {}
    }
}

try {
    while ($true) {
        $client = $tcpListener.AcceptTcpClient()
        # Обрабатываем в отдельном потоке, чтобы не блокировать приём новых соединений
        [System.Threading.Tasks.Task]::Run({ Handle-Client -Client $client }) | Out-Null
    }
} finally {
    $tcpListener.Stop()
    Write-Host "[i] Прокси остановлен." -ForegroundColor Yellow
}
