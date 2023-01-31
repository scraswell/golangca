package openssl

import (
	"fmt"
	"io"
	"log"
	"os/exec"
)

func getOpensslPath() string {
	openSslPath, err := exec.LookPath("openssl")
	if err != nil {
		panic("openssl was not found in the path.")
	}

	return openSslPath
}

func InvokeOpensslCommand(args ...string) (int, string, string) {
	sslCommand := exec.Command(
		getOpensslPath(),
		args...)

	log.Printf("invoked: %s", sslCommand.String())

	outPipe, err := sslCommand.StdoutPipe()
	if err != nil {
		panic(fmt.Errorf("unable to open stdout pipe: %w", err))
	}

	errPipe, err := sslCommand.StderrPipe()
	if err != nil {
		panic(fmt.Errorf("unable to open stderr pipe: %w", err))
	}

	if err := sslCommand.Start(); err != nil {
		panic(fmt.Errorf("command invocation failed: %w", err))
	}

	slurpOut, err := io.ReadAll(outPipe)
	if err != nil {
		panic(fmt.Errorf("unable read stdout: %w", err))
	}

	slurpErr, err := io.ReadAll(errPipe)
	if err != nil {
		panic(fmt.Errorf("unable read stderr: %w", err))
	}

	sslCommand.Wait()

	standardOutput := string(slurpOut)
	standardError := string(slurpErr)
	exitCode := sslCommand.ProcessState.ExitCode()

	return exitCode, standardOutput, standardError
}
