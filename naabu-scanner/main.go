package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Domain struct {
	ID   int
	Name string
}

var ErrNoResolvableIP = errors.New("no resolvable IP")

var (
	naabuConcurrency = getEnvOrDefault("NAABU_CONCURRENCY", "100")
	naabuRate        = getEnvOrDefault("NAABU_RATE", "5000")
	naabuRetries     = getEnvOrDefault("NAABU_RETRIES", "1")
	naabuTimeout     = getEnvOrDefault("NAABU_TIMEOUT", "500")
)

func getEnvOrDefault(key, def string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return def
}

func fetchAndClaimDomain(ctx context.Context, db *pgxpool.Pool) (Domain, bool, error) {
	var d Domain
	err := db.QueryRow(ctx, `
		WITH to_claim AS (
			SELECT d.id
			FROM domains d
			JOIN subdomains s ON s.domain_id = d.id
			WHERE d.status = 'completed'
			  AND s.ports_scanned = false
			  AND d.scanning_ports = false
			ORDER BY d.id
			LIMIT 1
			FOR UPDATE SKIP LOCKED
		)
		UPDATE domains
		SET scanning_ports = true
		FROM to_claim
		WHERE domains.id = to_claim.id
		RETURNING domains.id, domains.name;
	`).Scan(&d.ID, &d.Name)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Domain{}, false, nil
		}
		return Domain{}, false, err
	}
	return d, true, nil
}


func scanPortsForDomain(ctx context.Context, db *pgxpool.Pool, domainID int) error {
    defer func() {
		// Always unset scanning_ports, even on failure
		if _, err := db.Exec(ctx, `UPDATE domains SET scanning_ports = false WHERE id = $1`, domainID); err != nil {
            fmt.Printf("Failed to unset scanning_ports for domain %d: %v\n", domainID, err)
        }
	}()
    
    // Fetch unscanned subdomains
	rows, err := db.Query(ctx, `
		SELECT id, name FROM subdomains
		WHERE domain_id = $1 AND ports_scanned = false
	`, domainID)
	if err != nil {
		return err
	}
	defer rows.Close()

	subIDMap := make(map[string]int)
	var subdomains []string

	for rows.Next() {
		var id int
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return err
		}
		subIDMap[name] = id
		subdomains = append(subdomains, name)
	}

	if len(subdomains) == 0 {
		fmt.Println("No unscanned subdomains found.")
		return nil
	}

	fmt.Printf("Running naabu on %d subdomains...\n", len(subdomains))
	results, err := runNaabu(ctx, subdomains)

	if err != nil && !errors.Is(err, ErrNoResolvableIP) {
		fmt.Printf("Naabu failed: %v\n", err)
		return err
	}

	batch := &pgx.Batch{}
	for name, id := range subIDMap {
		if ports, ok := results[name]; ok {
			for _, port := range ports {
				batch.Queue(
					`INSERT INTO ports (subdomain_id, port) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
					id, port,
				)
			}
		}
		batch.Queue(`UPDATE subdomains SET ports_scanned = true WHERE id = $1`, id)
	}

	br := db.SendBatch(ctx, batch)
	return br.Close()
}

func runNaabu(ctx context.Context, subdomains []string) (map[string][]int, error) {
	cmd := exec.CommandContext(ctx, "naabu",
		"-silent",
        "-scan-type", "s",
		"-c", naabuConcurrency,
		"-rate", naabuRate,
		"-retries", naabuRetries,
		"-timeout", naabuTimeout,
	)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start naabu: %w", err)
	}

	// Write subdomains to stdin
	go func() {
		defer stdin.Close()
		for _, sub := range subdomains {
			io.WriteString(stdin, sub+"\n")
		}
	}()

	if err := cmd.Wait(); err != nil {
		if strings.Contains(stderr.String(), "no valid ipv4 or ipv6 targets were found") {
			return nil, ErrNoResolvableIP
		}
		return nil, fmt.Errorf("naabu error: %w\nstderr: %s", err, stderr.String())
	}

	results := make(map[string][]int)
	scanner := bufio.NewScanner(&stdout)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) != 2 {
			continue
		}
		sub := strings.TrimSpace(parts[0])
		port, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			continue
		}
		results[sub] = append(results[sub], port)
	}

	return results, nil
}

func main() {
	var dbConnStr = os.Getenv("DATABASE_URL")
	if dbConnStr == "" {
		log.Fatalf("Missing DATABASE_URL environment variable")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
			fmt.Printf("Checking for domains with unscanned subdomains...\n")
			domain, found, err := fetchAndClaimDomain(ctx, pool)
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

			start := time.Now()
			fmt.Printf("Scanning ports for domain: %s (ID: %d)\n", domain.Name, domain.ID)
			err = scanPortsForDomain(ctx, pool, domain.ID)
			duration := time.Since(start)
			if err != nil {
				fmt.Println("Scan error:", err)
				time.Sleep(5 * time.Second)
			} else {
				fmt.Printf("✅ Finished scanning domain %s in %v\n", domain.Name, duration)
			}
		}
	}
}
