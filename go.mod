module github.com/lvonguyen/cspm-aggregator

go 1.21

require (
	// AWS SDK
	github.com/aws/aws-sdk-go-v2 v1.24.0
	github.com/aws/aws-sdk-go-v2/config v1.26.0
	github.com/aws/aws-sdk-go-v2/service/securityhub v1.43.0

	// Azure SDK
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.4.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph v0.8.0

	// GCP SDK
	cloud.google.com/go/securitycenter v1.24.0
	google.golang.org/api v0.152.0

	// Utilities
	github.com/joho/godotenv v1.5.1
	go.uber.org/zap v1.26.0
	gopkg.in/yaml.v3 v3.0.1
)
