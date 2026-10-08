package web

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"unicode"

	"cobweb/internal/config"
	"cobweb/internal/firewall"
)

// renderFirewall re-renders the settings page with a message in the
// firewall panel. Validation failures use 400; operational outcomes
// (including "nft refused it") use 200, the same way the SQM panel
// reports a failed apply - the page itself rendered fine.
func (s *Server) renderFirewall(w http.ResponseWriter, status int, errMsg, okMsg string) {
	data := s.buildSettingsData("", "")
	data.FirewallError = errMsg
	data.FirewallSuccess = okMsg
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	s.renderSettingsData(w, data)
}

// applyIfEnabled pushes the current config to the kernel, but only when
// the firewall is switched on - rules edited while it's off are just
// saved, and never cause cobweb to touch nftables.
func (s *Server) applyIfEnabled() error {
	snap := s.cfg.Snapshot()
	if !snap.FirewallEnabled {
		return nil
	}
	return s.applyFirewall(snap)
}

// handleFirewallToggle switches cobweb's management of nftables on or
// off. Enabling that fails to apply is reverted to "off", so the saved
// setting never claims a firewall is running when it isn't.
func (s *Server) handleFirewallToggle(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	enable := r.PostFormValue("enabled") == "1"

	if err := s.cfg.SetFirewallEnabled(enable); err != nil {
		log.Printf("firewall toggle: %v", err)
		http.Error(w, "failed to save", http.StatusInternalServerError)
		return
	}
	if err := s.applyFirewall(s.cfg.Snapshot()); err != nil {
		log.Printf("firewall: apply after toggle(enable=%v): %v", enable, err)
		if enable {
			if rerr := s.cfg.SetFirewallEnabled(false); rerr != nil {
				log.Printf("firewall: revert enable flag: %v", rerr)
			}
			s.renderFirewall(w, http.StatusOK, "Not enabled - nothing was changed. "+err.Error(), "")
			return
		}
		s.renderFirewall(w, http.StatusOK, "Saved as off, but removing cobweb's nftables tables failed: "+err.Error(), "")
		return
	}

	if enable {
		s.renderFirewall(w, http.StatusOK, "", "Firewall enabled. cobweb now manages filtering, NAT and the rules below.")
		return
	}
	s.renderFirewall(w, http.StatusOK, "", "Firewall disabled and cobweb's nftables tables removed. Other tables on this box are untouched - if you retired your old ruleset, nothing is doing NAT right now until you re-enable this or load one.")
}

// handleFirewallAddRule validates and adds a port rule. A rule that
// can't be applied is not kept: nft applies atomically, so a failed
// apply changes nothing in the kernel, and the config is rolled back to
// match.
func (s *Server) handleFirewallAddRule(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	rule := config.PortRule{
		Name:     strings.TrimSpace(r.PostFormValue("name")),
		Kind:     strings.ToLower(strings.TrimSpace(r.PostFormValue("kind"))),
		Protocol: strings.ToLower(strings.TrimSpace(r.PostFormValue("protocol"))),
		Port:     strings.TrimSpace(r.PostFormValue("port")),
		ToIP:     strings.TrimSpace(r.PostFormValue("to_ip")),
		ToPort:   strings.TrimSpace(r.PostFormValue("to_port")),
		Source:   strings.TrimSpace(r.PostFormValue("source")),
	}
	if rule.Kind == config.RuleInput {
		rule.ToIP, rule.ToPort = "", "" // meaningless for a rule about this box itself
	}

	snap := s.cfg.Snapshot()
	if err := firewall.Validate(rule, snap.LANSegments); err != nil {
		s.renderFirewall(w, http.StatusBadRequest, "Rule not added: "+err.Error(), "")
		return
	}
	if rule.Name == "" {
		rule.Name = fmt.Sprintf("%s %s %s", rule.Kind, rule.Port, rule.Protocol)
	}

	added, err := s.cfg.AddPortRule(rule)
	if err != nil {
		log.Printf("add port rule: %v", err)
		http.Error(w, "failed to save", http.StatusInternalServerError)
		return
	}
	if err := s.applyIfEnabled(); err != nil {
		log.Printf("firewall: apply after add: %v", err)
		if rerr := s.cfg.RemovePortRule(added.ID); rerr != nil {
			log.Printf("firewall: roll back rule %s: %v", added.ID, rerr)
		}
		s.renderFirewall(w, http.StatusOK, "Rule not added - applying it failed and nothing was changed. "+err.Error(), "")
		return
	}

	if s.cfg.Snapshot().FirewallEnabled {
		s.renderFirewall(w, http.StatusOK, "", "Rule added and applied.")
		return
	}
	s.renderFirewall(w, http.StatusOK, "", "Rule saved. It takes effect once the firewall is enabled.")
}

func (s *Server) handleFirewallRemoveRule(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	id := strings.TrimSpace(r.PostFormValue("id"))
	if err := s.cfg.RemovePortRule(id); err != nil {
		log.Printf("remove port rule: %v", err)
		http.Error(w, "failed to save", http.StatusInternalServerError)
		return
	}
	if err := s.applyIfEnabled(); err != nil {
		log.Printf("firewall: apply after remove: %v", err)
		s.renderFirewall(w, http.StatusOK, "Rule removed from the config, but applying the change failed: "+err.Error(), "")
		return
	}
	s.renderFirewall(w, http.StatusOK, "", "Rule removed.")
}

// handleFirewallToggleRule turns a single rule off or on without
// deleting it, rolling the flag back if the change can't be applied.
func (s *Server) handleFirewallToggleRule(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	id := strings.TrimSpace(r.PostFormValue("id"))
	disable := r.PostFormValue("disabled") == "1"

	if err := s.cfg.SetPortRuleDisabled(id, disable); err != nil {
		s.renderFirewall(w, http.StatusBadRequest, err.Error(), "")
		return
	}
	if err := s.applyIfEnabled(); err != nil {
		log.Printf("firewall: apply after rule toggle: %v", err)
		if rerr := s.cfg.SetPortRuleDisabled(id, !disable); rerr != nil {
			log.Printf("firewall: roll back rule %s: %v", id, rerr)
		}
		s.renderFirewall(w, http.StatusOK, "Not changed - applying it failed and nothing was changed. "+err.Error(), "")
		return
	}
	if disable {
		s.renderFirewall(w, http.StatusOK, "", "Rule turned off.")
		return
	}
	s.renderFirewall(w, http.StatusOK, "", "Rule turned on.")
}

// handleFirewallDocker saves the Docker coexistence settings. They are
// validated before anything is stored, applied right away if the firewall is
// on, and rolled back to the previous values if the kernel refuses them.
func (s *Server) handleFirewallDocker(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	enabled := r.PostFormValue("docker_enabled") == "1"
	ifaces := strings.FieldsFunc(r.PostFormValue("docker_interfaces"), func(c rune) bool {
		return c == ',' || unicode.IsSpace(c)
	})
	source := strings.TrimSpace(r.PostFormValue("docker_wan_source"))

	prev := s.cfg.Snapshot()
	candidate := prev
	candidate.DockerEnabled, candidate.DockerInterfaces, candidate.DockerWANSource = enabled, ifaces, source
	if err := firewall.ValidateDocker(candidate); err != nil {
		s.renderFirewall(w, http.StatusBadRequest, "Docker settings not saved: "+err.Error(), "")
		return
	}

	if err := s.cfg.SetDocker(enabled, ifaces, source); err != nil {
		log.Printf("docker settings: %v", err)
		http.Error(w, "failed to save", http.StatusInternalServerError)
		return
	}
	if err := s.applyIfEnabled(); err != nil {
		log.Printf("firewall: apply after docker settings: %v", err)
		if rerr := s.cfg.SetDocker(prev.DockerEnabled, prev.DockerInterfaces, prev.DockerWANSource); rerr != nil {
			log.Printf("firewall: roll back docker settings: %v", rerr)
		}
		s.renderFirewall(w, http.StatusOK, "Docker settings not changed - applying them failed and nothing was changed. "+err.Error(), "")
		return
	}

	switch {
	case !s.cfg.Snapshot().FirewallEnabled:
		s.renderFirewall(w, http.StatusOK, "", "Docker settings saved. They take effect once the firewall is enabled.")
	case enabled:
		s.renderFirewall(w, http.StatusOK, "", "Docker containers are now allowed through and the change is live.")
	default:
		s.renderFirewall(w, http.StatusOK, "", "Docker containers are no longer given a path through the firewall.")
	}
}
