package actions

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/pinchtab/pinchtab/internal/cli/apiclient"
	"github.com/spf13/cobra"
)

// StateCurrent prints the current browser state.
func StateCurrent(client *http.Client, base, token string, cmd *cobra.Command) {
	tabID, _ := cmd.Flags().GetString("tab")
	params := url.Values{}
	if tabID != "" {
		params.Set("tabId", tabID)
	}

	result := apiclient.DoGetRaw(client, base, token, "/state", params)
	if result == nil {
		fmt.Fprintln(os.Stderr, "Failed to read current browser state")
		os.Exit(1)
	}

	var buf map[string]any
	if err := json.Unmarshal(result, &buf); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse response: %v\n", err)
		os.Exit(1)
	}

	out, _ := json.MarshalIndent(buf, "", "  ")
	fmt.Println(string(out))
}

// StateList lists all saved state files.
func StateList(client *http.Client, base, token string) {
	result := apiclient.DoGetRaw(client, base, token, "/state/list", nil)
	if result == nil {
		fmt.Fprintln(os.Stderr, "Failed to list state files")
		os.Exit(1)
	}

	var buf map[string]any
	if err := json.Unmarshal(result, &buf); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse response: %v\n", err)
		os.Exit(1)
	}

	out, _ := json.MarshalIndent(buf, "", "  ")
	fmt.Println(string(out))
}

// StateSave captures the current browser state and saves it to disk.
func StateSave(client *http.Client, base, token string, cmd *cobra.Command) {
	name, _ := cmd.Flags().GetString("name")
	encrypt, _ := cmd.Flags().GetBool("encrypt")
	tabID, _ := cmd.Flags().GetString("tab")

	body := map[string]any{
		"name":    name,
		"encrypt": encrypt,
	}
	if tabID != "" {
		body["tabId"] = tabID
	}

	result := apiclient.DoPost(client, base, token, "/state/save", body)
	if result == nil {
		fmt.Fprintln(os.Stderr, "Failed to save state")
		os.Exit(1)
	}
}

// StateLoad restores a saved state into the browser.
// Supports exact name or prefix-based loading (most recent match).
func StateLoad(client *http.Client, base, token string, cmd *cobra.Command) {
	name, _ := cmd.Flags().GetString("name")
	tabID, _ := cmd.Flags().GetString("tab")

	if name == "" {
		fmt.Fprintln(os.Stderr, "Error: --name is required")
		os.Exit(1)
	}

	body := map[string]any{
		"name": name,
	}
	if tabID != "" {
		body["tabId"] = tabID
	}

	result := apiclient.DoPost(client, base, token, "/state/load", body)
	if result == nil {
		fmt.Fprintln(os.Stderr, "Failed to load state")
		os.Exit(1)
	}
}

// StateShow shows full details of a saved state file.
func StateShow(client *http.Client, base, token string, cmd *cobra.Command) {
	name, _ := cmd.Flags().GetString("name")
	if name == "" {
		fmt.Fprintln(os.Stderr, "Error: --name is required")
		os.Exit(1)
	}

	params := url.Values{}
	params.Set("name", name)

	result := apiclient.DoGetRaw(client, base, token, "/state/show", params)
	if result == nil {
		fmt.Fprintln(os.Stderr, "Failed to show state")
		os.Exit(1)
	}

	var buf map[string]any
	if err := json.Unmarshal(result, &buf); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse response: %v\n", err)
		os.Exit(1)
	}

	out, _ := json.MarshalIndent(buf, "", "  ")
	fmt.Println(string(out))
}

// StateDelete removes a saved state file by name.
func StateDelete(client *http.Client, base, token string, cmd *cobra.Command) {
	name, _ := cmd.Flags().GetString("name")
	if name == "" {
		fmt.Fprintln(os.Stderr, "Error: --name is required")
		os.Exit(1)
	}

	params := url.Values{}
	params.Set("name", name)

	result := apiclient.DoDelete(client, base, token, "/state", params)
	if result == nil {
		fmt.Fprintln(os.Stderr, "Failed to delete state")
		os.Exit(1)
	}
}

// StateClean removes state files older than the given number of hours.
func StateClean(client *http.Client, base, token string, cmd *cobra.Command) {
	hours, _ := cmd.Flags().GetInt("older-than")

	body := map[string]any{
		"olderThanHours": hours,
	}

	result := apiclient.DoPost(client, base, token, "/state/clean", body)
	if result == nil {
		fmt.Fprintln(os.Stderr, "Failed to clean state files")
		os.Exit(1)
	}
}
