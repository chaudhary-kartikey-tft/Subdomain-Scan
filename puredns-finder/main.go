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
	"path/filepath"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Domain struct {
	ID         int
	Name       string
	InProgress bool
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

func fromPuredns(ctx context.Context, domain, wordlistPath, resolversPath, rateLimit string) ([]string, error) {
	outputFile, err := os.CreateTemp("", "puredns_output_*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(outputFile.Name())
	outputFile.Close()

	cmd := exec.CommandContext(ctx, "puredns",
		"bruteforce", wordlistPath, domain,
		"-r", resolversPath,
		"--write", outputFile.Name(),
        "--rate-limit", rateLimit,
	)

    cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("puredns failed: %w", err)
	}

	data, err := os.ReadFile(outputFile.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to read output file: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	var subs []string
	for _, line := range lines {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			subs = append(subs, trimmed)
		}
	}

	return subs, nil
}

func runHttpx(subdomains []string) ([]httpxResult, error) {
	cmd := exec.Command("httpx",
		"-json",
		"-sc", "-cl", "-ct", "-location",
		"-favicon", "-hash", "mmh3",
		"-jarm", "-rt", "-lc", "-wc", "-title", "-bp",
		"-server", "-td", "-method", "-websocket",
		"-ip", "-cname", "-cdn", "-probe",
		"--tls-grab", "--pipeline", "--http2", "--vhost",
		"-t", "500",
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

func fetchDomainNeedingPuredns(ctx context.Context, pool *pgxpool.Pool) (Domain, bool, error) {
	var d Domain

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return d, false, err
	}
	defer tx.Rollback(ctx) // Safe even if committed

	row := tx.QueryRow(ctx, `
		SELECT id, name FROM domains
		WHERE puredns_ran = false AND in_progress = false
		FOR UPDATE SKIP LOCKED
		LIMIT 1;
	`)

	if err := row.Scan(&d.ID, &d.Name); err != nil {
		return d, false, nil
	}

	_, err = tx.Exec(ctx, `
		UPDATE domains SET in_progress = true WHERE id = $1;
	`, d.ID)
	if err != nil {
		return d, false, err
	}

	if err := tx.Commit(ctx); err != nil {
		return d, false, err
	}

	d.InProgress = true
	return d, true, nil
}

func gatherSubdomains(ctx context.Context, pool *pgxpool.Pool, domain string, domainID int, wordlistPath, resolversPath, rateLimit string) {
	start := time.Now()
	fmt.Printf("[*] Starting puredns on %s...\n", domain)

	subs, err := fromPuredns(ctx, domain, wordlistPath, resolversPath, rateLimit)
	duration := time.Since(start)
	if err != nil {
		fmt.Printf("[!] puredns failed after %s: %v\n", duration, err)
		return
	}
	fmt.Printf("[✓] puredns finished in %s with %d subdomains\n", duration, len(subs))

	// Insert into DB
	if err := insertSubdomains(ctx, pool, domainID, subs, "puredns"); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed to insert subdomains: %v\n", err)
	}

	// Deduplicate
	subs = uniqueStrings(subs)

	// Filter already scanned
	newSubs, err := filterAlreadyProbed(ctx, pool, domainID, subs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed to filter subdomains: %v\n", err)
		return
	}
	if len(newSubs) == 0 {
		fmt.Println("[*] Skipping httpx: all subdomains already scanned.")
		return
	}

	// Run httpx
	fmt.Printf("[>] Running httpx on %d new subdomains...\n", len(newSubs))
	httpxResults, err := runHttpx(newSubs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] httpx error: %v\n", err)
		return
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

func markPurednsComplete(ctx context.Context, pool *pgxpool.Pool, domainID int) error {
	_, err := pool.Exec(ctx, `
		UPDATE domains
		SET puredns_ran = true, in_progress = false
		WHERE id = $1;
	`, domainID)
	return err
}

func downloadFileFromGCS(ctx context.Context, bucket, object string) (string, error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return "", fmt.Errorf("storage.NewClient: %w", err)
	}
	defer client.Close()

	rc, err := client.Bucket(bucket).Object(object).NewReader(ctx)
	if err != nil {
		return "", fmt.Errorf("object.NewReader: %w", err)
	}
	defer rc.Close()

	tmpFile, err := os.CreateTemp("", filepath.Base(object)+"_*")
	if err != nil {
		return "", fmt.Errorf("CreateTemp: %w", err)
	}
	defer tmpFile.Close()

	if _, err := io.Copy(tmpFile, rc); err != nil {
		return "", fmt.Errorf("io.Copy: %w", err)
	}

	return tmpFile.Name(), nil
}

func main() {
	var dbConnStr = os.Getenv("DATABASE_URL")
	if dbConnStr == "" {
		log.Fatalf("Missing DATABASE_URL environment variable")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	gcsBucket := os.Getenv("GCS_BUCKET")
	wordlistFile := os.Getenv("WORDLIST_FILE")
	resolversFile := os.Getenv("RESOLVERS_FILE")
    rateLimit := os.Getenv("RATE_LIMIT")

	wordlistPath, err := downloadFileFromGCS(ctx, gcsBucket, wordlistFile)
	if err != nil {
		log.Fatalf("Failed to download wordlist: %v", err)
	}
	defer os.Remove(wordlistPath)

	resolversPath, err := downloadFileFromGCS(ctx, gcsBucket, resolversFile)
	if err != nil {
		log.Fatalf("Failed to download resolvers: %v", err)
	}
	defer os.Remove(resolversPath)

	// Initialize database connection pool
	pool, err := pgxpool.New(ctx, dbConnStr)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v\n", err)
	}
	defer pool.Close()
	
	for {
		select {
		case <-ctx.Done():
			return
		default:
			domain, found, err := fetchDomainNeedingPuredns(ctx, pool)
			if err != nil {
				fmt.Println("Fetch error:", err)
				time.Sleep(10 * time.Second)
				continue
			}
			if !found {
				fmt.Println("No eligible domains found. Sleeping...")
				time.Sleep(30 * time.Second)
				continue
			}

			gatherSubdomains(ctx, pool, domain.Name, domain.ID, wordlistPath, resolversPath, rateLimit)

			err = markPurednsComplete(ctx, pool, domain.ID)
			if err != nil {
				fmt.Println("Update error:", err)
			}
		}
	}
}
