package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/pubsub"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func runCmd(ctx context.Context, name string, args ...string) ([]string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	var lines []string
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := cmd.Wait(); err != nil {
		return nil, err
	}
	return lines, nil
}

func fromFindomain(ctx context.Context, domain string) ([]string, error) {
	return runCmd(ctx, "findomain", "-t", domain, "-q")
}

func fromSubfinder(ctx context.Context, domain string) ([]string, error) {
	return runCmd(ctx, "subfinder", "-d", domain, "-silent")
}

func fromDnsrecon(ctx context.Context, domain string) ([]string, error) {
	outputFile, err := os.CreateTemp("", "dnsrecon_*.json")
	if err != nil {
		return nil, err
	}
	outputFile.Close()
	defer os.Remove(outputFile.Name())

	cmd := exec.CommandContext(ctx, "dnsrecon", "-d", domain, "-t", "crt", "-j", outputFile.Name())

	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("dnsrecon crt failed: %w", err)
	}

	data, err := os.ReadFile(outputFile.Name())
	if err != nil {
		return nil, err
	}

	var entries []map[string]interface{}
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("dnsrecon output parse error: %w", err)
	}

	seen := make(map[string]struct{})
	for _, entry := range entries {
		if nameRaw, ok := entry["name"]; ok {
			if name, ok := nameRaw.(string); ok && strings.HasSuffix(name, domain) {
				seen[name] = struct{}{}
			}
		}
	}

	var subs []string
	for sub := range seen {
		subs = append(subs, sub)
	}
	return subs, nil
}

type subResult struct {
	Source string
	Subs   []string
	Err    error
}

func gatherSubdomainsAsync(ctx context.Context, pool *pgxpool.Pool, domain string, domainID int) []subResult {
	sources := []struct {
		name string
		fn   func(context.Context, string) ([]string, error)
	}{
		{"findomain", fromFindomain},
		{"subfinder", fromSubfinder},
		{"dnsrecon", fromDnsrecon},
	}

	results := make(chan subResult, len(sources))
	subdomainChan := make(chan []string)

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for subs := range subdomainChan {
			if len(subs) == 0 {
				continue
			}

			newSubs, err := filterAlreadyProbed(ctx, pool, domainID, subs)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] Failed to filter subdomains: %v\n", err)
				continue
			}
			if len(newSubs) == 0 {
				fmt.Println("[*] Skipping httpx: all subdomains already scanned.")
				continue
			}

			fmt.Printf("[>] Running httpx on %d new subdomains...\n", len(newSubs))
			httpxResults, err := runHttpx(newSubs)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] httpx error: %v\n", err)
				continue
			}
			fmt.Printf("[✓] httpx finished, got %d results.\n", len(httpxResults))

			if err := insertHttpxResults(ctx, pool, domainID, httpxResults); err != nil {
				fmt.Fprintf(os.Stderr, "[!] Failed to insert httpx results: %v\n", err)
			} else {
				fmt.Println("[✓] httpx results inserted into database.")
			}

			if err := markSubdomainsProbed(ctx, pool, domainID, newSubs); err != nil {
				fmt.Fprintf(os.Stderr, "[!] Failed to mark subdomains as probed: %v\n", err)
			} else {
				fmt.Printf("[✓] Marked %d subdomains as probed.\n", len(newSubs))
			}
		}
	}()

	for _, s := range sources {
		go func(name string, fn func(context.Context, string) ([]string, error)) {
			start := time.Now()
			fmt.Printf("[*] Starting %s...\n", name)

			localCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
			defer cancel()

			subs, err := fn(localCtx, domain)

			duration := time.Since(start)
			if err != nil {
				fmt.Printf("[!] %s failed after %s: %v\n", name, duration, err)
			} else {
				fmt.Printf("[✓] %s finished in %s with %d subdomains\n", name, duration, len(subs))

				if err := insertSubdomains(ctx, pool, domainID, subs, name); err != nil {
					fmt.Fprintf(os.Stderr, "[!] Failed to insert subdomains from %s: %v\n", name, err)
				} else {
					fmt.Printf("[✓] Subdomains from %s inserted into DB.\n", name)
				}

				subs = uniqueStrings(subs)
				subdomainChan <- subs
			}

			results <- subResult{Source: name, Subs: subs, Err: err}
		}(s.name, s.fn)
	}

	var allResults []subResult
	for range sources {
		res := <-results
		allResults = append(allResults, res)
	}

	close(subdomainChan)
	wg.Wait()

	return allResults
}

func filterAlreadyProbed(ctx context.Context, pool *pgxpool.Pool, domainID int, subs []string) ([]string, error) {
	query := `
		SELECT name
		FROM subdomains
		WHERE domain_id = $1 AND name = ANY($2) AND probed = FALSE
	`
	rows, err := pool.Query(ctx, query, domainID, subs)
	if err != nil {
		return nil, fmt.Errorf("querying unprobed subdomains: %w", err)
	}
	defer rows.Close()

	var filtered []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		filtered = append(filtered, name)
	}
	return filtered, nil
}

func ensureDomain(ctx context.Context, pool *pgxpool.Pool, domain string) (int, string, error) {
	var id int
	var status string

	err := pool.QueryRow(ctx, `
        INSERT INTO domains (name, status)
        VALUES ($1, 'pending')
        ON CONFLICT (name) DO NOTHING
        RETURNING id, status`, domain).Scan(&id, &status)

	if err == pgx.ErrNoRows {
		err = pool.QueryRow(ctx, `
            SELECT id, status FROM domains
            WHERE name = $1`, domain).Scan(&id, &status)
	}

	return id, status, err
}

func markSubdomainsProbed(ctx context.Context, pool *pgxpool.Pool, domainID int, names []string) error {
	_, err := pool.Exec(ctx, `
		UPDATE subdomains
		SET probed = TRUE
		WHERE domain_id = $1 AND name = ANY($2)
	`, domainID, names)
	if err != nil {
		return fmt.Errorf("marking subdomains as probed: %w", err)
	}
	return nil
}

func markDomainComplete(ctx context.Context, pool *pgxpool.Pool, domainID int) error {
	_, err := pool.Exec(ctx, `
		UPDATE domains
		SET status = 'completed'
		WHERE id = $1
	`, domainID)
	if err != nil {
		return fmt.Errorf("failed to update domain status: %w", err)
	}
	return nil
}

// func ensureSubdomain(ctx context.Context, pool *pgxpool.Pool, domainID int, subdomain string) (int, error) {
// 	var subdomainID int
// 	err := pool.QueryRow(ctx, `
//         INSERT INTO subdomains (domain_id, name, source)
//         VALUES ($1, $2, 'httpx')
//         ON CONFLICT (domain_id, name) DO NOTHING
//         RETURNING id
//     `, domainID, subdomain).Scan(&subdomainID)

// 	if err == pgx.ErrNoRows {
// 		err = pool.QueryRow(ctx, `
// 			SELECT id FROM subdomains
// 			WHERE domain_id = $1 AND name = $2
// 		`, domainID, subdomain).Scan(&subdomainID)
// 	}

// 	if err != nil {
// 		return 0, fmt.Errorf("failed to get or insert subdomain %s: %w", subdomain, err)
// 	}
// 	return subdomainID, nil
// }

func insertSubdomains(ctx context.Context, pool *pgxpool.Pool, domainID int, subdomains []string, source string) error {
	query := `
        INSERT INTO subdomains (domain_id, name, source)
        VALUES ($1, $2, $3)
        ON CONFLICT (domain_id, name) DO NOTHING`
	for _, sub := range subdomains {
		if _, err := pool.Exec(ctx, query, domainID, sub, source); err != nil {
			return err
		}
	}
	return nil
}

type httpxResult struct {
	Timestamp     string   `json:"timestamp"`
	URL           string   `json:"url"`
	Input         string   `json:"input"`
	Host          string   `json:"host"`
	Port          string   `json:"port"`
	Scheme        string   `json:"scheme"`
	Method        string   `json:"method"`
	Path          string   `json:"path"`
	StatusCode    int      `json:"status_code"`
	ContentLength int      `json:"content_length"`
	ContentType   string   `json:"content_type"`
	Location      string   `json:"location"`
	WebServer     string   `json:"webserver"`
	Title         string   `json:"title"`
	BodyPreview   string   `json:"body_preview"`
	Time          string   `json:"time"`
	Words         int      `json:"words"`
	Lines         int      `json:"lines"`
	VHost         bool     `json:"vhost"`
	HTTP2         bool     `json:"http2"`
	Pipeline      bool     `json:"pipeline"`
	CDN           bool     `json:"cdn"`
	CDNName       string   `json:"cdn_name"`
	CDNType       string   `json:"cdn_type"`
	JARMHash      string   `json:"jarm_hash"`
	A             []string `json:"a"`
	AAAA          []string `json:"aaaa"`
	Tech          []string `json:"tech"`
	Failed        bool     `json:"failed"`
	Resolvers     []string `json:"resolvers"`

	Hash struct {
		BodyMMH3   string `json:"body_mmh3"`
		HeaderMMH3 string `json:"header_mmh3"`
	} `json:"hash"`

	TLS struct {
		Host          string   `json:"host"`
		Port          string   `json:"port"`
		ProbeStatus   bool     `json:"probe_status"`
		TLSVersion    string   `json:"tls_version"`
		Cipher        string   `json:"cipher"`
		NotBefore     string   `json:"not_before"`
		NotAfter      string   `json:"not_after"`
		SubjectDN     string   `json:"subject_dn"`
		SubjectCN     string   `json:"subject_cn"`
		SubjectAN     []string `json:"subject_an"`
		Serial        string   `json:"serial"`
		IssuerDN      string   `json:"issuer_dn"`
		IssuerCN      string   `json:"issuer_cn"`
		IssuerOrg     []string `json:"issuer_org"`
		TLSConnection string   `json:"tls_connection"`
		SNI           string   `json:"sni"`

		FingerprintHash struct {
			MD5    string `json:"md5"`
			SHA1   string `json:"sha1"`
			SHA256 string `json:"sha256"`
		} `json:"fingerprint_hash"`
	} `json:"tls"`

	Knowledgebase struct {
		PageType string `json:"PageType"`
		PHash    int    `json:"pHash"`
	} `json:"knowledgebase"`
}

func runHttpx(subdomains []string) ([]httpxResult, error) {
	cmd := exec.Command("httpx",
		"-json",
		"-sc", "-cl", "-ct", "-location",
		"-favicon", "-hash", "mmh3",
		"-jarm", "-rt", "-lc", "-wc", "-title", "-bp",
		"-server", "-td", "-method", "-websocket",
		"-ip", "-cname", "-cdn", "-probe",
		"--tls-grab", "-t", "500",
	)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start httpx: %w", err)
	}

	go func() {
		defer stdin.Close()
		for _, sub := range subdomains {
			fmt.Fprintln(stdin, sub)
		}
	}()

	var results []httpxResult
	scanner := bufio.NewScanner(stdout)

	for scanner.Scan() {
		var result httpxResult
		line := scanner.Text()

		if len(line) == 0 {
			continue
		}
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			fmt.Println("httpx unmarshalling error", err)
			continue
		}

		if result.Failed {
			continue
		}

		results = append(results, result)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner error: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("httpx command failed: %w", err)
	}

	return results, nil
}

func insertHttpxResults(ctx context.Context, pool *pgxpool.Pool, domainID int, results []httpxResult) error {

	for _, res := range results {

		var subdomainID int
		err := pool.QueryRow(ctx, `
			SELECT id FROM subdomains
			WHERE domain_id = $1 AND name = $2
		`, domainID, res.Input).Scan(&subdomainID)

		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Subdomain not found in DB for input: %s\n", res.Input)
			continue
		}

		_, err = pool.Exec(ctx, `
        INSERT INTO httpx_results (
            subdomain_id, scheme, port, status_code, title, server, host, url,
            content_length, is_alive, cdn_name, cdn_type, content_type,
            redirect_location, a_records, aaaa_records,
            words, lines, response_time_ms, method, pipeline, http2, vhost,
            body_hash_mmh3, header_hash_mmh3, jarm_hash, body_preview,
            tech, tls_version, tls_cipher, tls_not_before, tls_not_after,
            tls_subject_cn, tls_issuer_cn, tls_serial, tls_sni,
            tls_md5, tls_sha1, tls_sha256
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8,
            $9, $10, $11, $12, $13,
            $14, $15, $16,
            $17, $18, $19, $20, $21, $22, $23,
            $24, $25, $26, $27,
            $28, $29, $30, $31, $32,
            $33, $34, $35, $36,
            $37, $38, $39
        )
        ON CONFLICT (subdomain_id, host, url, port) DO NOTHING`,
			subdomainID, res.Scheme, res.Port, res.StatusCode, res.Title, res.WebServer, res.Host, res.URL,
			res.ContentLength, !res.Failed, res.CDNName, res.CDNType, res.ContentType,
			res.Location, res.A, res.AAAA,
			res.Words, res.Lines, parseMillis(res.Time), res.Method, res.Pipeline, res.HTTP2, res.VHost,
			res.Hash.BodyMMH3, res.Hash.HeaderMMH3, res.JARMHash, res.BodyPreview,
			res.Tech, res.TLS.TLSVersion, res.TLS.Cipher, parseHttpxTime(res.TLS.NotBefore), parseHttpxTime(res.TLS.NotAfter),
			res.TLS.SubjectCN, res.TLS.IssuerCN, res.TLS.Serial, res.TLS.SNI,
			res.TLS.FingerprintHash.MD5, res.TLS.FingerprintHash.SHA1, res.TLS.FingerprintHash.SHA256,
		)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error inserting httpx result: %v\n", err)
		}
	}

	return nil
}

func parseMillis(duration string) int {
	var ms float64
	fmt.Sscanf(duration, "%fms", &ms)
	return int(ms)
}

func parseHttpxTime(s string) interface{} {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	return t
}

func uniqueStrings(input []string) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, s := range input {
		if _, exists := seen[s]; !exists {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}
	return result
}

func main() {
	var dbConnStr = os.Getenv("DATABASE_URL")
	if dbConnStr == "" {
		log.Fatalf("Missing DATABASE_URL environment variable")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	projectID := os.Getenv("GCP_PROJECT")
	subID := os.Getenv("PUBSUB_SUBSCRIPTION")
	if projectID == "" || subID == "" {
		log.Fatalf("Missing GCP_PROJECT or PUBSUB_SUBSCRIPTION environment variable")
	}

	// Initialize Pub/Sub client
	client, err := pubsub.NewClient(ctx, projectID)
	if err != nil {
		log.Fatalf("Failed to create PubSub client: %v\n", err)
	}
	defer client.Close()

	// Initialize database connection pool
	pool, err := pgxpool.New(ctx, dbConnStr)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v\n", err)
	}
	defer pool.Close()

	sub := client.Subscription(subID)
	sub.ReceiveSettings.MaxOutstandingMessages = 1
	sub.ReceiveSettings.NumGoroutines = 1

	// Continuously receive messages from Pub/Sub
	err = sub.Receive(ctx, func(cctx context.Context, msg *pubsub.Message) {
		domain := strings.TrimSpace(string(msg.Data))
		fmt.Printf("Received domain: %s\n", domain)

		// Process each domain
		domainID, status, err := ensureDomain(cctx, pool, domain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to ensure domain %s: %v\n", domain, err)
			msg.Nack() // Nack the message to retry later
			return
		}

		if status == "completed" {
			fmt.Fprintf(os.Stderr, "Domain %s already completed. Skipping.\n", domain)
			msg.Ack()
			return
		}

		gatherSubdomainsAsync(cctx, pool, domain, domainID)

		// Mark domain as complete
		err = markDomainComplete(cctx, pool, domainID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to mark domain %s complete: %v\n", domain, err)
			msg.Nack()
			return
		}
		fmt.Printf("Domain marked complete: %s\n", domain)

		msg.Ack() // Acknowledge the message
	})

	if err != nil {
		log.Fatalf("PubSub receive error: %v\n", err)
	}
}
