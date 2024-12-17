// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	mondoov1 "go.mondoo.com/mondoo-go"
)

// ConvertListValue converts a slice of strings to a types.List.
func ConvertListValue(list []string) types.List {
	var valueList []attr.Value
	for _, str := range list {
		valueList = append(valueList, types.StringValue(str))
	}
	// Ensure the list is of type types.StringType
	return types.ListValueMust(types.StringType, valueList)
}

// ConvertMapValue converts a map of strings to a types.Map.
func ConvertMapValue(m map[string]interface{}) types.Map {
	var valueMap = make(map[string]attr.Value)
	for key, value := range m {
		switch v := value.(type) {
		case string:
			valueMap[key] = types.StringValue(v)
		default:
			// Handle other types if necessary
			valueMap[key] = types.StringValue("")
		}
	}
	// Ensure the map is of type types.StringType
	return types.MapValueMust(types.StringType, valueMap)
}

// ConvertSliceStrings converts a types.List to a slice of strings.
func ConvertSliceStrings(list types.List) (slice []mondoov1.String) {
	ctx := context.Background()
	allowlist, _ := list.ToListValue(ctx)
	allowlist.ElementsAs(ctx, &slice, true)
	return
}
