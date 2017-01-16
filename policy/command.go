package policy

import (
	"os/exec"
	"strings"

	"github.com/Sirupsen/logrus"
)

func execCmd(cmd *exec.Cmd) error {
	logrus.Debugf("cmd: %+v", cmd)
	cmdOutput, err := cmd.CombinedOutput()
	if err != nil {
		logrus.Errorf("err: %v, cmdOut=%v", err, string(cmdOutput))
		return err
	}

	return nil
}

func buildCommand(cmdStr string) *exec.Cmd {
	cmd := strings.Split(strings.TrimSpace(cmdStr), " ")
	return exec.Command(cmd[0], cmd[1:]...)
}

func executeCommand(cmdStr string) error {
	cmd := buildCommand(cmdStr)
	return execCmd(cmd)
}
