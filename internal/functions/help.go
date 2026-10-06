package functions

import (
	"wifisec/internal/constants"
	"wifisec/internal/utilities"
)

func HelpUsage(arguements []string) error {
	utilities.Info(
		"%s",
		constants.DeveloperMetadata.String(),
	)

	return nil
}
