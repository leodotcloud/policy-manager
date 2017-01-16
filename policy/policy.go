package policy

import (
	"fmt"

	"github.com/Sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

const (
	// ActionAllow action for the policy
	ActionAllow string = "allow"
	// ActionDeny action for the policy
	ActionDeny string = "deny"
)

// StrStack for 'stack' string
// StrService for 'service' string
// StrLink for 'link' string
const (
	StrStack   string = "stack"
	StrService string = "service"
	StrLink    string = "link"
)

// SrcDst is used to hold information for from/to fields of the the policy
// Stack holds the stack name
// Service holds the service name (stackname.servicename)
// Selector holds the value of the selector (com.company.label1=value1)
type SrcDst struct {
	Stack    string `yaml:"stack"`
	Service  string `yaml:"service"`
	Selector string `yaml:"selector"`
}

// BetweenSelection ...
type BetweenSelection struct {
	Stacks   []string `yaml:"stacks"`
	Services []string `yaml:"services"`
	Selector string   `yaml:"selector"`
	GroupBy  string   `yaml:"group_by"`
}

// Policy is used to hold one of the multiple Policies inside one big NetworkPolicy
type Policy struct {
	From    *SrcDst           `yaml:"from"`
	To      *SrcDst           `yaml:"to"`
	Ports   []string          `yaml:"ports"`
	Within  string            `yaml:"within"`
	Between *BetweenSelection `yaml:"between"`
	Action  string            `yaml:"action"`
}

// NetworkPolicy is one big holder, which has multiple Policies
type NetworkPolicy struct {
	DefaultPolicyAction string   `yaml:"defaultPolicyAction"`
	Policies            []Policy `yaml:"policies"`
}

// ParseNetworkPolicy is used to parse the input yaml representation of the network policy and perform basic validations
func ParseNetworkPolicy(npStr string) (*NetworkPolicy, error) {
	//logrus.Debugf("Parsing Network policy: %#+v", npStr)

	var np NetworkPolicy
	np.DefaultPolicyAction = ActionAllow

	err := yaml.Unmarshal([]byte(npStr), &np)
	if err != nil {
		logrus.Errorf("error: %v", err)
		return nil, err
	}

	if err := np.Validate(); err != nil {
		logrus.Errorf("error validating policy: %v", npStr)
		logrus.Errorf("error: %v", err)
		return nil, err
	}

	return &np, nil
}

// Validate runs basic validations on the network policy
func (np *NetworkPolicy) Validate() error {
	if np.DefaultPolicyAction != ActionAllow && np.DefaultPolicyAction != ActionDeny {
		return fmt.Errorf("defaultPolicyAction has be either 'allow' or 'deny' but got: %v", np.DefaultPolicyAction)
	}

	for _, p := range np.Policies {
		//logrus.Infof("Working on: %#v", p)

		if err := p.Validate(); err != nil {
			//logrus.Errorf("Parsing policy: %#+v got error: %v", p, err)
			return err
		}
	}
	return nil
}

// Validate runs basic validations on the policy
func (p *Policy) Validate() error {
	if p.Within == "" && p.Between == nil && p.To == nil && p.From == nil {
		return fmt.Errorf("a valid policy needs 'within' or  'to' & 'from' or 'between'")
	}

	if p.Within != "" {
		if p.Within != StrStack && p.Within != StrService && p.Within != StrLink {
			return fmt.Errorf("invalid value specified for within: %v", p.Within)
		}

		if p.From != nil || p.To != nil || p.Ports != nil || p.Between != nil {
			return fmt.Errorf("when using 'within': 'between' or 'from' & 'to' or 'ports' are not allowed")
		}
	} else if p.Between != nil {
		if p.From != nil || p.To != nil || p.Ports != nil || p.Within != "" {
			return fmt.Errorf("when using 'between': 'within' or 'from' & 'to' or 'ports' are not allowed")
		}
	} else if p.To == nil || p.From == nil {
		return fmt.Errorf("a policy needs both 'from' & 'to' to be valid")
	}

	if p.Action != ActionAllow && p.Action != ActionDeny {
		return fmt.Errorf("a policy action has be either 'allow' or 'deny' but got: %v", p.Action)
	}

	//TODO: Check if the ports are of the form 1234 or 1234/udp or 1234/tcp

	if p.From != nil {
		if p.From.Stack == "" && p.From.Service == "" && p.From.Selector == "" {
			return fmt.Errorf("'from' needs atleast one of: [stack, service, selector]")
		}

	}

	if p.To != nil {
		if p.To.Stack == "" && p.To.Service == "" && p.To.Selector == "" {
			return fmt.Errorf("'to' needs atleast one of: [stack, service, selector]")
		}
	}

	// TODO: Check if more than one from/to are specified

	return nil
}
