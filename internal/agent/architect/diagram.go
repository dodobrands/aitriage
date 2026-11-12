package architect

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Component struct {
	Name string
	Type string // "app" | "db" | "cache" | "proxy" | "storage"
}

// GenerateMermaidDiagram analyzes the project and generates a Mermaid diagram.
// Detects components by presence of key files and dependencies.
func GenerateMermaidDiagram(projectPath string) (string, error) {
	components := DetectComponents(projectPath)
	if len(components) == 0 {
		return "", fmt.Errorf("could not detect project components")
	}

	var sb strings.Builder
	sb.WriteString("graph TD\n")

	// Main application is always present
	mainApp := findMainApp(components)
	fmt.Fprintf(&sb, "    %s[\"%s\"]\n", sanitize(mainApp.Name), mainApp.Name)

	for _, c := range components {
		if c.Name == mainApp.Name {
			continue
		}
		nodeID := sanitize(c.Name)
		var icon string
		switch c.Type {
		case "db":
			icon = "🗄️"
		case "cache":
			icon = "⚡"
		case "proxy":
			icon = "🔀"
		case "storage":
			icon = "📦"
		case "message_broker":
			icon = "📨"
		default:
			icon = "🔧"
		}
		fmt.Fprintf(&sb, "    %s[\"%s %s\"]\n", nodeID, icon, c.Name)
		fmt.Fprintf(&sb, "    %s --> %s\n", sanitize(mainApp.Name), nodeID)
	}

	return sb.String(), nil
}

func DetectComponents(projectPath string) []Component {
	var components []Component

	// Detect main application type
	if fileExists(filepath.Join(projectPath, "go.mod")) {
		components = append(components, Component{Name: "Go App", Type: "app"})
	} else if fileExists(filepath.Join(projectPath, "package.json")) {
		components = append(components, Component{Name: "Node.js App", Type: "app"})
	} else if fileExists(filepath.Join(projectPath, "requirements.txt")) {
		components = append(components, Component{Name: "Python App", Type: "app"})
	} else {
		components = append(components, Component{Name: "Application", Type: "app"})
	}

	// Detect dependencies by file presence and docker-compose content
	composeFiles := []string{"docker-compose.yml", "docker-compose.yaml"}
	for _, cf := range composeFiles {
		data, err := os.ReadFile(filepath.Join(projectPath, cf))
		if err != nil {
			continue
		}
		content := strings.ToLower(string(data))
		if strings.Contains(content, "postgres") || strings.Contains(content, "postgresql") {
			components = append(components, Component{Name: "PostgreSQL", Type: "db"})
		}
		if strings.Contains(content, "mysql") || strings.Contains(content, "mariadb") {
			components = append(components, Component{Name: "MySQL", Type: "db"})
		}
		if strings.Contains(content, "redis") {
			components = append(components, Component{Name: "Redis", Type: "cache"})
		}
		if strings.Contains(content, "nginx") {
			components = append(components, Component{Name: "Nginx", Type: "proxy"})
		}
		if strings.Contains(content, "minio") || strings.Contains(content, "s3") {
			components = append(components, Component{Name: "MinIO/S3", Type: "storage"})
		}
		if strings.Contains(content, "mongo") {
			components = append(components, Component{Name: "MongoDB", Type: "db"})
		}
		if strings.Contains(content, "elasticsearch") {
			components = append(components, Component{Name: "Elasticsearch", Type: "db"})
		}
		if strings.Contains(content, "rabbitmq") {
			components = append(components, Component{Name: "RabbitMQ", Type: "message_broker"})
		}
		if strings.Contains(content, "kafka") {
			components = append(components, Component{Name: "Kafka", Type: "message_broker"})
		}
	}

	return components
}

func findMainApp(components []Component) Component {
	for _, c := range components {
		if c.Type == "app" {
			return c
		}
	}
	return Component{Name: "Application", Type: "app"}
}

func sanitize(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, " ", "_"), ".", "_")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
