package types

import "maps"

// AccessControlContext holds ground truth identifiers for forensic
// evaluation of authorization boundary testing. The judge uses these
// to determine whether returned data belongs to the authenticated user,
// a known victim, or an unknown third party.
type AccessControlContext struct {
	// AuthenticatedIdentifiers are key=value pairs that describe the
	// attacker's own identity (e.g., tenant_id=acme-corp, user_id=viewer_acme).
	// Required.
	AuthenticatedIdentifiers map[string]string `yaml:"authenticated_identifiers" json:"authenticated_identifiers"`

	// VictimIdentifiers are key=value pairs that describe the victim's
	// identity (e.g., tenant_id=globex-corp). Optional — when provided,
	// enables two-identifier mode for stronger forensic proof.
	VictimIdentifiers map[string]string `yaml:"victim_identifiers,omitempty" json:"victim_identifiers,omitempty"`

	// IdentityFieldHints are field names to look for in target responses
	// (e.g., tenant_id, user_id, owner, created_by). Config values
	// override context-discovered values.
	IdentityFieldHints []string `yaml:"identity_field_hints,omitempty" json:"identity_field_hints,omitempty"`
}

// TwoIdentifierMode returns true when victim identifiers are provided,
// enabling stronger forensic comparison.
func (ac *AccessControlContext) TwoIdentifierMode() bool {
	return len(ac.VictimIdentifiers) > 0
}

// MergeAccessControl merges config-provided ground truth with context-discovered
// values. Config always takes priority. Returns a merged copy.
func MergeAccessControl(config, discovered *AccessControlContext) AccessControlContext {
	result := AccessControlContext{
		AuthenticatedIdentifiers: make(map[string]string),
	}

	// Start with discovered values.
	if discovered != nil {
		maps.Copy(result.AuthenticatedIdentifiers, discovered.AuthenticatedIdentifiers)
		if len(discovered.VictimIdentifiers) > 0 {
			result.VictimIdentifiers = make(map[string]string)
			maps.Copy(result.VictimIdentifiers, discovered.VictimIdentifiers)
		}
		result.IdentityFieldHints = append(result.IdentityFieldHints, discovered.IdentityFieldHints...)
	}

	// Config overrides discovered values.
	if config != nil {
		maps.Copy(result.AuthenticatedIdentifiers, config.AuthenticatedIdentifiers)
		if len(config.VictimIdentifiers) > 0 {
			if result.VictimIdentifiers == nil {
				result.VictimIdentifiers = make(map[string]string)
			}
			maps.Copy(result.VictimIdentifiers, config.VictimIdentifiers)
		}
		if len(config.IdentityFieldHints) > 0 {
			// Config hints replace discovered hints entirely.
			result.IdentityFieldHints = config.IdentityFieldHints
		}
	}

	return result
}
