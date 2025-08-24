//////////////////////////////////////////
//     TUNISIA, 08 24 2025              //
//     www.dotcom.tn                    //
//     waf / nginx / linux / debian 12  //
//////////////////////////////////////////


package main

import (
        "fmt"
        "github.com/hpcloud/tail"
        "os/exec"
        "regexp"
        "strconv"
        "strings"
        "sync"
        "time"
)

// Log représente une entrée de log
type Log struct {
        Timestamp time.Time
        SourceIP  string
        URL       string
        Request   string // Requête complète
        Status    int
}

// Analyzer analyse les logs et détecte les attaques
type Analyzer struct {
        requestCounts map[string]int
        threshold     int
        blockedIPs    map[string]bool
        mu            sync.Mutex
}

// NewAnalyzer crée un nouvel analyseur
func NewAnalyzer(threshold int) *Analyzer {
        return &Analyzer{
                requestCounts: make(map[string]int),
                threshold:     threshold,
                blockedIPs:    make(map[string]bool),
        }
}

// MaliciousPatterns définit les motifs d'attaques, y compris OWASP
var MaliciousPatterns = []*regexp.Regexp{
        // Patterns existants
        regexp.MustCompile(`(?i)\.env`),                    // Accès à des fichiers de configuration
        regexp.MustCompile(`(?i)/owa/`),                    // Tentatives d'accès à Outlook Web Access
        regexp.MustCompile(`(?i)/boaform/`),                // Pages d'administration spécifiques
        regexp.MustCompile(`(?i)/api/client/update`),       // Abus d'API
        regexp.MustCompile(`^(?i)CONNECT\b`),               // Méthode CONNECT non standard
        regexp.MustCompile(`[\x00-\x1F\x7F-\xFF]`),        // Caractères non-ASCII (ex. données binaires)
        regexp.MustCompile(`\\x[0-9A-Fa-f]{2}`),           // Séquence hexadécimale échappée

        // OWASP A01: Broken Access Control
        regexp.MustCompile(`(?i)/(admin|wp-admin|config|setup|login\.php)`), // Pages d'administration
        regexp.MustCompile(`(?i)/(\.git|\.htaccess|phpinfo\.php)`),          // Fichiers sensibles

        // OWASP A03: Injection
        regexp.MustCompile(`(?i)(select|union|insert|delete|drop|1=1|--|%27|%3B)`), // SQL Injection
        regexp.MustCompile(`(?i)(;|&&|\|\||\` + "`" + `|whoami|cat\s+/etc|exec|cmd)`), // Command Injection

        // OWASP A07: Cross-Site Scripting (XSS)
        regexp.MustCompile(`(?i)(<script|javascript:|onerror=|onload=|%3Cscript%3E)`), // XSS

        // OWASP A10: SSRF
        regexp.MustCompile(`(?i)(http://(localhost|127\.0\.0\.1|169\.254\.169\.254))`), // SSRF
}


// IsMaliciousRequest vérifie si une requête est suspecte
func IsMaliciousRequest(request string) bool {
        for _, pattern := range MaliciousPatterns {
                if pattern.MatchString(request) {
                        fmt.Printf("Debug: Requête malveillante détectée dans '%s'\n", request)
                        return true
                }
        }
        fmt.Printf("Debug: Requête non malveillante: '%s'\n", request)
        return false
}

// IsIPBlocked vérifie si une IP est déjà bloquée par iptables
func (a *Analyzer) IsIPBlocked(ip string) bool {
        if ip == "localhost" {
                return false // Ne pas vérifier localhost
        }

        cmd := exec.Command("iptables", "-L", "INPUT", "-v", "-n")
        output, err := cmd.Output()
        if err != nil {
                fmt.Printf("Erreur lors de la vérification des règles iptables: %v\n", err)
                return false
        }

        // Chercher une règle DROP pour l'IP
        lines := strings.Split(string(output), "\n")
        for _, line := range lines {
                if strings.Contains(line, "DROP") && strings.Contains(line, ip) {
                        return true
                }
        }
        return false
}

// ProcessLog traite un log et détecte les attaques
func (a *Analyzer) ProcessLog(log Log) {
        a.mu.Lock()
        defer a.mu.Unlock()

        // Ignorer si l'IP est déjà bloquée dans blockedIPs ou iptables
        if a.blockedIPs[log.SourceIP] || a.IsIPBlocked(log.SourceIP) {
                return
        }

        // Vérifier si la requête est malveillante
        if IsMaliciousRequest(log.Request) {
                fmt.Printf("Requête malveillante détectée de %s (Requête: %s) ! Bloquage de l'IP.\n", log.SourceIP, log.Request)
                a.blockedIPs[log.SourceIP] = true

                // Appliquer une règle iptables (optionnel, nécessite sudo)
                if log.SourceIP != "localhost" {
                        cmd := exec.Command("iptables", "-A", "INPUT", "-s", log.SourceIP, "-j", "DROP")
                        if err := cmd.Run(); err != nil {
                                fmt.Printf("Erreur lors du blocage de %s avec iptables: %v\n", log.SourceIP, err)
                        } else {
                                fmt.Printf("IP %s bloquée avec succès via iptables\n", log.SourceIP)
                        }
                }
                return
        }

        
   // Afficher les métriques avant tout traitement
        fmt.Printf("Log traité: %s, IP: %s, URL: %s, Status: %d\n", log.Timestamp.Format(time.RFC3339), log.SourceIP, log.URL, log.Status)

        // Incrémenter le compteur de requêtes pour l'IP
        a.requestCounts[log.SourceIP]++

        // Vérifier si l'IP dépasse le seuil
        if a.requestCounts[log.SourceIP] >= a.threshold {
                fmt.Printf("Attaque DDoS détectée de %s ! Bloquage de l'IP.\n", log.SourceIP)
                a.blockedIPs[log.SourceIP] = true

                // Appliquer une règle iptables (optionnel, nécessite sudo)
                if log.SourceIP != "localhost" {
                        cmd := exec.Command("iptables", "-A", "INPUT", "-s", log.SourceIP, "-j", "DROP")
                        if err := cmd.Run(); err != nil {
                                fmt.Printf("Erreur lors du blocage de %s avec iptables: %v\n", log.SourceIP, err)
                        } else {
                                fmt.Printf("IP %s bloquée avec succès via iptables\n", log.SourceIP)
                        }
                }
        }
}


// CleanUp nettoie les compteurs périodiquement
func (a *Analyzer) CleanUp() {
        for {
                time.Sleep(10 * time.Second)
                a.mu.Lock()
                for ip := range a.requestCounts {
                        a.requestCounts[ip] = 0 // Réinitialiser les compteurs
                }
                a.mu.Unlock()
        }
}

// ParseNginxLog parse une ligne de log Nginx (format combiné)
func ParseNginxLog(line string) (Log, error) {
        // Regex pour le format combiné de Nginx
        re := regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]+)" (\d+) (\d+) "([^"]*)" "([^"]*)"$`)
        matches := re.FindStringSubmatch(line)
        if len(matches) != 8 {
                return Log{}, fmt.Errorf("log format invalid")
        }

        // Extraire l'IP et normaliser localhost
        ip := matches[1]
        if ip == "127.0.0.1" || ip == "::1" {
                ip = "localhost"
        }

        // Extraire le timestamp
        timeStr := matches[2]
        timestamp, err := time.Parse("02/Jan/2006:15:04:05 -0700", timeStr)
        if err != nil {
                return Log{}, fmt.Errorf("invalid timestamp: %v", err)
        }

        // Extraire la requête complète
        request := matches[3]
        // Tenter de séparer la requête pour extraire l'URL, avec une gestion des cas malformés
        url := ""
        requestParts := strings.SplitN(request, " ", 3)
        if len(requestParts) >= 2 {
                url = requestParts[1]
        } else {
                url = request // Utiliser la requête complète si elle ne peut pas être séparée
        }

   // Extraire le code de statut HTTP
        status, err := strconv.Atoi(matches[4])
        if err != nil || status < 100 || status > 599 {
                return Log{}, fmt.Errorf("invalid HTTP status code: %s", matches[4])
        }

        return Log{
                Timestamp: timestamp,
                SourceIP:  ip,
                URL:       url,
                Request:   request,
                Status:    status,
        }, nil
}

// ReadNginxLogs lit les logs Nginx en temps réel
func ReadNginxLogs(logChan chan Log, logFile string) {
        t, err := tail.TailFile(logFile, tail.Config{Follow: true, ReOpen: true})
        if err != nil {
                fmt.Printf("Erreur lors de l'ouverture du fichier de log: %v\n", err)
                return
        }

        for line := range t.Lines {
                log, err := ParseNginxLog(line.Text)
                if err != nil {
                        fmt.Printf("Erreur lors du parsing du log: %v\n", err)
                        continue
                }
                logChan <- log
        }
}

func main() {
        logChan := make(chan Log, 100)
        analyzer := NewAnalyzer(10) // Seuil de 10 pour détecter les attaques DDoS

        // Lancer la lecture des logs Nginx 
        // Nginx  on debian 12
        go ReadNginxLogs(logChan, "/var/log/nginx/access.log")

        // Lancer le nettoyage périodique
        go analyzer.CleanUp()

        // Traiter les logs en temps réel
        for log := range logChan {
                analyzer.ProcessLog(log)
        }
}
