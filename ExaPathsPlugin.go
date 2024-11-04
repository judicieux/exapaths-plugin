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
        // Ajoutez ici les chemins spécifiques que vous souhaitez vérifier
        return []l9format.WebPluginRequest{
                {Method: "GET", Path: "/content../.git/config"},
                {Method: "GET", Path: "/images../.git/config"},
                {Method: "GET", Path: "/js../.git/config"},
                {Method: "GET", Path: "/media../.git/config"},
                {Method: "GET", Path: "/static../.git/config"},
                {Method: "GET", Path: "/.github/workflows/build.yaml"},
                {Method: "GET", Path: "/.github/workflows/build.yml"},
                {Method: "GET", Path: "/.gitlab-ci.yml"},
        }
}

func (ExaPathsPlugin) GetName() string {
        return "ExaPathsPlugin"
}

func (ExaPathsPlugin) GetStage() string {
        return "open"
}

func (plugin ExaPathsPlugin) Verify(request l9format.WebPluginRequest, response l9format.WebPluginResponse, event *l9format.L9Event, options map[string]string) bool {
        if response.Response.StatusCode != 200 {
                return false
        }
        if strings.Contains(strings.ToLower(string(response.Body)), "repositoryformatversion") {
                event.Service.Software.Name = "Git Repository"
                event.Leak.Type = "path_exposure"
                event.Leak.Severity = "high"
                event.Summary = "Found exposed git configuration file"
                return true
        }
        return false
}
