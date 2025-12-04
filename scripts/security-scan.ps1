# Script de scan de securite
Write-Host "SCAN DE SECURITE - Guardia Project" -ForegroundColor Cyan
Write-Host "===================================" -ForegroundColor Cyan
Write-Host ""

# 1. Test npm audit
Write-Host "1. Scan des dependances npm..." -ForegroundColor Yellow
cd backend

$vulnerabilities = 0
try {
    npm audit --json > audit-result.json 2>&1
    if (Test-Path audit-result.json) {
        $audit = Get-Content audit-result.json | ConvertFrom-Json
        if ($audit.metadata.vulnerabilities) {
            $v = $audit.metadata.vulnerabilities
            $vulnerabilities = $v.info + $v.low + $v.moderate + $v.high + $v.critical
            Write-Host "   Total vulnerabilites: $vulnerabilities" -ForegroundColor White
        }
        Remove-Item audit-result.json
    }
} catch {
    Write-Host "   Erreur lors du scan npm audit" -ForegroundColor Red
}

if ($vulnerabilities -eq 0) {
    $depScore = 100
} else {
    $depScore = [Math]::Max(0, 100 - ($vulnerabilities * 5))
}
Write-Host "   Score: $depScore/100" -ForegroundColor Green
Write-Host ""

# 2. Test des headers de securite
Write-Host "2. Verification des headers de securite..." -ForegroundColor Yellow

$headersToCheck = @("X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection", "Strict-Transport-Security", "Content-Security-Policy")
$headersPresent = 0

try {
    $response = Invoke-WebRequest -Uri "http://localhost:3001" -Method Get -ErrorAction Stop
    
    foreach ($header in $headersToCheck) {
        if ($response.Headers[$header]) {
            $headersPresent++
            Write-Host "   OK: $header" -ForegroundColor Green
        } else {
            Write-Host "   MANQUANT: $header" -ForegroundColor Red
        }
    }
} catch {
    Write-Host "   ERREUR: Serveur non accessible sur http://localhost:3001" -ForegroundColor Red
    Write-Host "   Demarrez le serveur avec: npm start" -ForegroundColor Yellow
}

$headerScore = ($headersPresent / $headersToCheck.Count) * 100
Write-Host "   Score: $headerScore/100" -ForegroundColor $(if($headerScore -gt 50){"Green"}else{"Red"})
Write-Host ""

# 3. Test HTTPS
Write-Host "3. Verification HTTPS..." -ForegroundColor Yellow
$httpsScore = 0
Write-Host "   HTTPS non configure" -ForegroundColor Red
Write-Host "   Score: $httpsScore/100" -ForegroundColor Red
Write-Host ""

# 4. Tests unitaires
Write-Host "4. Tests unitaires..." -ForegroundColor Yellow
$testOutput = npm test 2>&1
if ($LASTEXITCODE -eq 0) {
    $testScore = 100
    Write-Host "   Tous les tests passent" -ForegroundColor Green
} else {
    $testScore = 50
    Write-Host "   Certains tests echouent" -ForegroundColor Yellow
}
Write-Host "   Score: $testScore/100" -ForegroundColor Green
Write-Host ""

# Calcul du score final
$finalScore = ($depScore * 0.3) + ($headerScore * 0.3) + ($httpsScore * 0.2) + ($testScore * 0.2)
$finalScore = [Math]::Round($finalScore, 2)

Write-Host "===================================" -ForegroundColor Cyan
Write-Host "SCORE FINAL: $finalScore/100" -ForegroundColor $(if($finalScore -gt 70){"Green"}elseif($finalScore -gt 40){"Yellow"}else{"Red"})
Write-Host "===================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "RECOMMANDATIONS:" -ForegroundColor Cyan
if ($depScore -lt 100) {
    Write-Host "  - Executez 'npm audit fix' pour corriger les vulnerabilites" -ForegroundColor Yellow
}
if ($headerScore -lt 100) {
    Write-Host "  - Ajoutez les headers de securite dans Express" -ForegroundColor Yellow
}
if ($httpsScore -eq 0) {
    Write-Host "  - Configurez HTTPS pour la production" -ForegroundColor Yellow
}

cd ..
