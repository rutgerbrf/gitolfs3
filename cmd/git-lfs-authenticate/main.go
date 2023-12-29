package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func die(msg string, args ...any) {
	fmt.Fprint(os.Stderr, "Error: ")
	fmt.Fprintf(os.Stderr, msg, args...)
	fmt.Fprint(os.Stderr, "\n")
	os.Exit(1)
}

func main() {
	if len(os.Args) != 3 {
		die("expected 2 arguments [path, operation], got %d", len(os.Args)-1)
	}

	path := strings.TrimPrefix(strings.TrimSuffix(os.Args[1], ".git"), "/")
	operation := os.Args[2]

	if operation != "download" && operation != "upload" {
		die("expected operation to be in {upload, download}, got %s", operation)
	}

	user := os.Getenv("GL_USER")
	if user == "" {
		die("expected Gitolite user env (GL_USER) to be set")
	}

	gitolitePerm := "R"
	if operation == "upload" {
		gitolitePerm = "W"
	}

	// gitolite access -q: returns only exit code
	cmd := exec.Command("gitolite", "access", "-q", path, user, gitolitePerm)
	err := cmd.Run()
	permGranted := err == nil
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		die("failed to query Gitolite access information")
	}
}
