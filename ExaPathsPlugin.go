package path_exposure

import (
	"github.com/LeakIX/l9format"
	"strings"
)

type ExaPathsPlugin struct {
	l9format.ServicePluginBase
}

func (ExaPathsPlugin) GetVersion() (int, int, int) {
	return 0, 0, 1
}

func (ExaPathsPlugin) GetRequests() []l9format.WebPluginRequest {
	return []l9format.WebPluginRequest{{
		Method:  "GET",
		Path:    "/.env.example",
		Headers: map[string]string{},
		Body:    []byte(""),
	}}
}

func (ExaPathsPlugin) GetName() string {
	return "EnvExampleHttpPlugin"
}

func (ExaPathsPlugin) GetStage() string {
	return "open"
}

func (plugin ExaPathsPlugin) Verify(request l9format.WebPluginRequest, response l9format.WebPluginResponse, event *l9format.L9Event, options map[string]string) (hasLeak bool) {
	// Vérification si la requête correspond, si le code HTTP est 200 et si la taille du corps est raisonnable
	if !request.EqualAny(plugin.GetRequests()) || response.Response.StatusCode != 200 {
		return false
	}
	lowerBody := strings.ToLower(string(response.Body))
	if len(lowerBody) < 10 {
		return false
	}
	// Vérification du motif "DB_HOST="
	if strings.Contains(lowerBody, "db_host=") {
		event.Service.Software.Name = "EnvironmentFile"
		event.Leak.Type = "config_leak"
		event.Leak.Severity = "high"
		event.AddTag("potential-db-credentials")
		event.Summary = "Found DB_HOST in /.env.example:\n" + string(response.Body)
		return true
	}
	return false
}
