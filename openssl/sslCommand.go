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

	log.Printf(fmt.Sprintf("Invoked: %s", sslCommand.String()))

	outPipe, err := sslCommand.StdoutPipe()
	if err != nil {
		panic(fmt.Errorf("Unable to open stdout pipe: %w", err))
	}

	errPipe, err := sslCommand.StderrPipe()
	if err != nil {
		panic(fmt.Errorf("Unable to open stderr pipe: %w", err))
	}

	if err := sslCommand.Start(); err != nil {
		panic(fmt.Errorf("Command invocation failed: %w", err))
	}

	slurpOut, err := io.ReadAll(outPipe)
	if err != nil {
		panic(fmt.Errorf("Unable read stdout: %w", err))
	}

	slurpErr, err := io.ReadAll(errPipe)
	if err != nil {
		panic(fmt.Errorf("Unable read stderr: %w", err))
	}

	sslCommand.Wait()

	standardOutput := fmt.Sprintf("%s", slurpOut)
	standardError := fmt.Sprintf("%s", slurpErr)
	exitCode := sslCommand.ProcessState.ExitCode()

	return exitCode, standardOutput, standardError
}
