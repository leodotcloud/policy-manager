package policy

import (
	"testing"

	"github.com/Sirupsen/logrus"
)

func init() {
	logrus.SetLevel(logrus.DebugLevel)
}

func TestParseNetworkPolicyWithValidPolicies(t *testing.T) {
	var err error

	np1str := `
defaultPolicyAction: allow
policies:
  - from:
      stack: alphastack
    to:
      stack: bravostack
    ports:
      - 80/tcp
      - 8080
    action: allow
  - within: stack
    action: allow
  - within: service
    action: allow
  - from:
      service: stackone.zuluservice
    to:
      service: stackone.xrayservice
    action: allow
  - from:
      selector: com.company.label1=value1
    to:
      selector: com.company.label2=value2
    action: deny
`
	logrus.Debugf("TestParseNetworkPolicy")

	_, err = ParseNetworkPolicy(np1str)
	if err != nil {
		logrus.Errorf("error parsing policy: %v", err)
	}

	noerrnp0str := ``
	_, err = ParseNetworkPolicy(noerrnp0str)
	if err != nil {
		t.Errorf("NOT expecting error but got: %v", err)
	}

	noerrnp1str := `
defaultPolicyAction: deny
policies:
`
	_, err = ParseNetworkPolicy(noerrnp1str)
	if err != nil {
		t.Errorf("NOT expecting error but got: %v", err)
	}

	noerrnp2str := `
defaultPolicyAction: allow
policies:
  - from:
      stack: alphastack
    to:
      stack: bravostack
    ports:
      - 80/tcp
      - 8080
    action: allow
  - within: stack
    action: allow
`
	_, err = ParseNetworkPolicy(noerrnp2str)
	if err != nil {
		t.Errorf("NOT expecting error but got: %v", err)
	}

	noerrnp3str := `
defaultPolicyAction: allow
policies:
  - within: service
    action: deny

`
	_, err = ParseNetworkPolicy(noerrnp3str)
	if err != nil {
		t.Errorf("NOT expecting error but got: %v", err)
	}

	noerrnp4str := `
policies:
`
	_, err = ParseNetworkPolicy(noerrnp4str)
	if err != nil {
		t.Errorf("NOT expecting error but got: %v", err)
	}

	noerrnp5str := `
defaultPolicyAction: allow
policies:
  - from:
      stack: alphastack
      service: serviceone.alphastack
    to:
      stack: bravostack
    action: allow
`
	_, err = ParseNetworkPolicy(noerrnp5str)
	if err != nil {
		t.Errorf("not expecting got: %v", err)
	}

	noerrnp6str := `
defaultPolicyAction: allow
policies:
  - from:
      stack: alphastack
    to:
      stack: bravostack
      service: serviceone.bravostack
    action: allow
`
	_, err = ParseNetworkPolicy(noerrnp6str)
	if err != nil {
		t.Errorf("not expecting got: %v", err)
	}

	noerrnp7str := `
defaultPolicyAction: allow
policies:
  - between:
      stacks:
      - alphastack
      - bravostack
    action: allow
`
	_, err = ParseNetworkPolicy(noerrnp7str)
	if err != nil {
		t.Errorf("not expecting got: %v", err)
	}

}

func TestParseNetworkPolicyWithInvalidPolicies(t *testing.T) {
	var err error
	errnp1str := `
defaultPolicyAction: has_to_be_allow_or_deny
policies:
  - within: stack
    action: allow
`
	_, err = ParseNetworkPolicy(errnp1str)
	if err == nil {
		t.Errorf("expecting error got nil")
	}

	errnp2str := `
defaultPolicyAction: deny
policies:
  - within: stack
    action: has_to_be_allow_or_deny
`
	_, err = ParseNetworkPolicy(errnp2str)
	if err == nil {
		t.Errorf("expecting error got nil")
	}

	errnp3str := `
defaultPolicyAction: deny
policies:
  - within: has_to_be_stack_or_service_or_link
    action: deny
`
	_, err = ParseNetworkPolicy(errnp3str)
	if err == nil {
		t.Errorf("expecting error got nil")
	}

	errnp4str := `
defaultPolicyAction: deny
policies:
  within: has_to_be_stack_or_service_or_link
    action: deny
`
	_, err = ParseNetworkPolicy(errnp4str)
	if err == nil {
		t.Errorf("expecting error got nil")
	}

	errnp5str := `
defaultPolicyAction: allow
policies:
  - from:
      stack: alphastack
    ports:
      - 80/tcp
      - 8080
    action: allow
`
	_, err = ParseNetworkPolicy(errnp5str)
	if err == nil {
		t.Errorf("expecting error got nil")
	}

	errnp6str := `
defaultPolicyAction: allow
policies:
  - to:
      stack: bravostack
    ports:
      - 80/tcp
      - 8080
    action: allow
`
	_, err = ParseNetworkPolicy(errnp6str)
	if err == nil {
		t.Errorf("expecting error got nil")
	}

	errnp7str := `
defaultPolicyAction: allow
policies:
  - ports:
      - 80/tcp
      - 8080
    action: allow
`
	_, err = ParseNetworkPolicy(errnp7str)
	if err == nil {
		t.Errorf("expecting error got nil")
	}

	errnp8str := `
defaultPolicyAction: allow
policies:
  - from:
      stack: alphastack
    to:
      stack: bravostack
    action: has_to_be_allow_or_deny
`
	_, err = ParseNetworkPolicy(errnp8str)
	if err == nil {
		t.Errorf("expecting error got nil")
	}

}
