package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/stateweaver/stateweaver/lab/api"
)

var (
	vulnPort   int
	secPort    int
	foreground bool
)

var labCmd = &cobra.Command{
	Use:   "lab",
	Short: "Manage local test labs (vulnerable and secure target APIs)",
}

var labStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the local vulnerable and secure test lab APIs",
	Long:  "Spins up the vulnerable target API (port 8080) and secure target API (port 8081) for reproducible differential authorization testing.",
	RunE: func(cmd *cobra.Command, args []string) error {
		pidFile := filepath.Join(".stateweaver", "lab.pid")

		if !foreground {
			// Check if already running
			if data, err := os.ReadFile(pidFile); err == nil && len(data) > 0 {
				pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
				if isProcessRunning(pid) {
					fmt.Printf("[i] Lab server is already running with PID %d\n", pid)
					fmt.Printf("    • Vulnerable API: http://127.0.0.1:%d\n", vulnPort)
					fmt.Printf("    • Secure API:     http://127.0.0.1:%d\n", secPort)
					return nil
				}
			}

			// Spawn detached background process
			exe, err := os.Executable()
			if err != nil {
				exe = "stateweaver"
			}

			args := []string{"lab", "start", "--foreground", fmt.Sprintf("--port=%d", vulnPort), fmt.Sprintf("--secure-port=%d", secPort)}
			child := exec.Command(exe, args...)
			if err := child.Start(); err != nil {
				return fmt.Errorf("failed to start background lab: %w", err)
			}

			_ = os.MkdirAll(".stateweaver", 0750)
			_ = os.WriteFile(pidFile, []byte(strconv.Itoa(child.Process.Pid)), 0644)

			fmt.Printf("[+] StateWeaver Lab started in background (PID %d)\n", child.Process.Pid)
			fmt.Printf("    • Vulnerable API: http://127.0.0.1:%d\n", vulnPort)
			fmt.Printf("    • Secure API:     http://127.0.0.1:%d\n", secPort)
			fmt.Println("\nRun 'stateweaver lab stop' to shut down lab instances.")
			return nil
		}

		// Foreground mode
		vulnSrv := api.NewLabServer(vulnPort, false)
		secSrv := api.NewLabServer(secPort, true)

		errChan := make(chan error, 2)
		go func() {
			errChan <- vulnSrv.Start()
		}()
		go func() {
			errChan <- secSrv.Start()
		}()

		fmt.Printf("[+] StateWeaver Vulnerable Lab listening on http://127.0.0.1:%d\n", vulnPort)
		fmt.Printf("[+] StateWeaver Secure Lab listening on http://127.0.0.1:%d\n", secPort)
		fmt.Println("[*] Press Ctrl+C to terminate lab servers.")

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

		select {
		case err := <-errChan:
			return fmt.Errorf("lab server startup error: %w", err)
		case <-sigChan:
			fmt.Println("\n[*] Shutting down lab servers...")
			_ = vulnSrv.Stop(context.Background())
			_ = secSrv.Stop(context.Background())
			_ = os.Remove(pidFile)
			fmt.Println("[✓] Lab servers stopped.")
			return nil
		}
	},
}

var labStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop active local test lab APIs",
	RunE: func(cmd *cobra.Command, args []string) error {
		pidFile := filepath.Join(".stateweaver", "lab.pid")
		data, err := os.ReadFile(pidFile)
		if err != nil {
			fmt.Println("[i] No running lab PID file found.")
			return nil
		}

		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil || pid <= 0 {
			_ = os.Remove(pidFile)
			fmt.Println("[i] Stale or invalid PID file removed.")
			return nil
		}

		process, err := os.FindProcess(pid)
		if err != nil {
			_ = os.Remove(pidFile)
			fmt.Printf("[i] Process %d not found.\n", pid)
			return nil
		}

		if err := process.Kill(); err != nil {
			fmt.Printf("[!] Could not kill process %d: %v\n", pid, err)
		} else {
			fmt.Printf("[✓] Stopped lab process (PID %d)\n", pid)
		}

		_ = os.Remove(pidFile)
		return nil
	},
}

func isProcessRunning(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Windows, FindProcess always succeeds, so we test with signal 0 or err
	return p != nil
}

func init() {
	labStartCmd.Flags().IntVar(&vulnPort, "port", 8080, "Port for vulnerable target API")
	labStartCmd.Flags().IntVar(&secPort, "secure-port", 8081, "Port for secure target API")
	labStartCmd.Flags().BoolVar(&foreground, "foreground", false, "Run lab servers in foreground")

	labCmd.AddCommand(labStartCmd)
	labCmd.AddCommand(labStopCmd)
}

