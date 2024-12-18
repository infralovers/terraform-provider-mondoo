package provider

import (
	"context"
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	mondoov1 "go.mondoo.com/mondoo-go"
)

var _ resource.Resource = (*integrationAzureResource)(nil)

func NewIntegrationAzureResource() resource.Resource {
	return &integrationAzureResource{}
}

type integrationAzureResource struct {
	client *ExtendedGqlClient
}

type integrationAzureResourceModel struct {
	// scope
	SpaceID types.String `tfsdk:"space_id"`

	// integration details
	Mrn                   types.String `tfsdk:"mrn"`
	Name                  types.String `tfsdk:"name"`
	ClientId              types.String `tfsdk:"client_id"`
	TenantId              types.String `tfsdk:"tenant_id"`
	SubscriptionAllowList types.List   `tfsdk:"subscription_allow_list"`
	SubscriptionDenyList  types.List   `tfsdk:"subscription_deny_list"`
	ScanVms               types.Bool   `tfsdk:"scan_vms"`

	// credentials
	Credential integrationAzureCredentialModel `tfsdk:"credentials"`
}

type integrationAzureCredentialModel struct {
	PEMFile types.String `tfsdk:"pem_file"`
}

func (m integrationAzureResourceModel) GetConfigurationOptions() *mondoov1.AzureConfigurationOptionsInput {

	ctx := context.Background()
	var listAllow []mondoov1.String
	allowlist, _ := m.SubscriptionAllowList.ToListValue(ctx)
	allowlist.ElementsAs(ctx, &listAllow, true)

	var listDeny []mondoov1.String
	denylist, _ := m.SubscriptionDenyList.ToListValue(ctx)
	denylist.ElementsAs(ctx, &listDeny, true)

	opts := &mondoov1.AzureConfigurationOptionsInput{
		TenantID:               mondoov1.String(m.TenantId.ValueString()),
		ClientID:               mondoov1.String(m.ClientId.ValueString()),
		SubscriptionsAllowlist: &listAllow,
		SubscriptionsDenylist:  &listDeny,
		ScanVms:                mondoov1.NewBooleanPtr(mondoov1.Boolean(m.ScanVms.ValueBool())),
		Certificate:            mondoov1.NewStringPtr(mondoov1.String(m.Credential.PEMFile.ValueString())),
	}

	return opts
}

func (r *integrationAzureResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_integration_azure"
}

// NotEqualValidator ensures two string attributes are not equal.
type NotEqualValidator struct {
	OtherAttribute string
}

// ValidateString performs the validation.
func (v NotEqualValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	// Retrieve the value of the other attribute
	var otherAttr types.String
	diags := req.Config.GetAttribute(ctx, path.Root(v.OtherAttribute), &otherAttr)
	if diags.HasError() || otherAttr.IsNull() || otherAttr.IsUnknown() {
		// Skip validation if the other attribute is not set
		return
	}

	// Check if the values of the two attributes are equal
	if req.ConfigValue.ValueString() == otherAttr.ValueString() {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Attributes Cannot Be Equal",
			fmt.Sprintf("The value of '%s' cannot be the same as '%s'.", req.Path.String(), v.OtherAttribute),
		)
	}
}

// Description returns a plain-text description of the validator's purpose.
func (v NotEqualValidator) Description(ctx context.Context) string {
	return "Ensures that two attributes are not equal."
}

// MarkdownDescription returns a markdown-formatted description of the validator's purpose.
func (v NotEqualValidator) MarkdownDescription(ctx context.Context) string {
	return "Ensures that two attributes are not equal."
}

// NewNotEqualValidator is a convenience function to create an instance of the validator.
func NewNotEqualValidator(otherAttribute string) validator.String {
	return &NotEqualValidator{
		OtherAttribute: otherAttribute,
	}
}

func (r *integrationAzureResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: `Continuously scan Microsoft Azure subscriptions and resources for misconfigurations and vulnerabilities. See [Mondoo documentation](https://mondoo.com/docs/platform/infra/cloud/azure/azure-integration-scan-subscription/) for more details.`,
		Attributes: map[string]schema.Attribute{
			"space_id": schema.StringAttribute{
				MarkdownDescription: "Mondoo Space Identifier. If it is not provided, the provider space is used.",
				Optional:            true,
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"mrn": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Integration identifier",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Name of the integration.",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(250),
				},
			},
			"client_id": schema.StringAttribute{
				MarkdownDescription: "Azure Client ID.",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.RegexMatches(regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`), "Client ID must be a valid GUID."),
					NewNotEqualValidator("tenant_id"),
				},
			},
			"tenant_id": schema.StringAttribute{
				MarkdownDescription: "Azure Tenant ID.",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.RegexMatches(regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`), "Tenant ID must be a valid GUID."),
					NewNotEqualValidator("client_id"),
				},
			},
			"scan_vms": schema.BoolAttribute{
				MarkdownDescription: "Scan VMs.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"subscription_allow_list": schema.ListAttribute{
				MarkdownDescription: "List of Azure subscriptions to scan.",
				Optional:            true,
				Computed:            true,
				Default:             listdefault.StaticValue(types.ListValueMust(types.StringType, []attr.Value{})),
				ElementType:         types.StringType,
				Validators: []validator.List{
					// Validate only this attribute or other_attr is configured.
					listvalidator.ConflictsWith(path.Expressions{
						path.MatchRoot("subscription_deny_list"),
					}...),
				},
			},
			"subscription_deny_list": schema.ListAttribute{
				MarkdownDescription: "List of Azure subscriptions to exclude from scanning.",
				Optional:            true,
				Computed:            true,
				Default:             listdefault.StaticValue(types.ListValueMust(types.StringType, []attr.Value{})),
				ElementType:         types.StringType,
				Validators: []validator.List{
					// Validate only this attribute or other_attr is configured.
					listvalidator.ConflictsWith(path.Expressions{
						path.MatchRoot("subscription_allow_list"),
					}...),
				},
			},
			"credentials": schema.SingleNestedAttribute{
				Required: true,
				Attributes: map[string]schema.Attribute{
					"pem_file": schema.StringAttribute{
						MarkdownDescription: "PEM file for Azure integration.",
						Required:            true,
						Sensitive:           true,
					},
				},
			},
		},
	}
}

func (r *integrationAzureResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*ExtendedGqlClient)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *http.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	r.client = client
}

func (r *integrationAzureResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {

	var data integrationAzureResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	space, err := r.client.ComputeSpace(data.SpaceID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid Configuration", err.Error())
		return
	}
	ctx = tflog.SetField(ctx, "space_mrn", space.MRN())

	// Do GraphQL request to API to create the resource.
	tflog.Debug(ctx, "Creating integration")
	integration, err := r.client.CreateIntegration(ctx,
		space.MRN(),
		data.Name.ValueString(),
		mondoov1.ClientIntegrationTypeAzure,
		mondoov1.ClientIntegrationConfigurationInput{
			AzureConfigurationOptions: data.GetConfigurationOptions(),
		})
	if err != nil {
		resp.Diagnostics.
			AddError("Client Error",
				fmt.Sprintf("Unable to create Azure integration, got error: %s", err),
			)
		return
	}

	// trigger integration to gather results quickly after the first setup
	// NOTE: we ignore the error since the integration state does not depend on it
	_, err = r.client.TriggerAction(ctx, string(integration.Mrn), mondoov1.ActionTypeRunScan)
	if err != nil {
		resp.Diagnostics.
			AddWarning("Client Error",
				fmt.Sprintf("Unable to trigger integration, got error: %s", err),
			)
	}

	// Save space mrn into the Terraform state.
	data.Mrn = types.StringValue(string(integration.Mrn))
	data.Name = types.StringValue(string(integration.Name))
	data.SpaceID = types.StringValue(space.ID())

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *integrationAzureResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data integrationAzureResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Read API call logic
	integration, err := r.client.GetClientIntegration(ctx, data.Mrn.ValueString())
	if err != nil {
		resp.State.RemoveResource(ctx)
		return
	}

	model := integrationAzureResourceModel{
		SpaceID:               types.StringValue(integration.SpaceID()),
		Mrn:                   types.StringValue(integration.Mrn),
		Name:                  types.StringValue(integration.Name),
		ClientId:              types.StringValue(integration.ConfigurationOptions.AzureConfigurationOptions.ClientId),
		TenantId:              types.StringValue(integration.ConfigurationOptions.AzureConfigurationOptions.TenantId),
		SubscriptionAllowList: ConvertListValue(integration.ConfigurationOptions.AzureConfigurationOptions.SubscriptionsWhitelist),
		SubscriptionDenyList:  ConvertListValue(integration.ConfigurationOptions.AzureConfigurationOptions.SubscriptionsBlacklist),
		Credential: integrationAzureCredentialModel{
			PEMFile: types.StringValue(data.Credential.PEMFile.ValueString()),
		},
		ScanVms: types.BoolValue(integration.ConfigurationOptions.AzureConfigurationOptions.ScanVms),
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

func (r *integrationAzureResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data integrationAzureResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Do GraphQL request to API to update the resource.
	opts := mondoov1.ClientIntegrationConfigurationInput{
		AzureConfigurationOptions: data.GetConfigurationOptions(),
	}

	_, err := r.client.UpdateIntegration(ctx,
		data.Mrn.ValueString(),
		data.Name.ValueString(),
		mondoov1.ClientIntegrationTypeAzure,
		opts,
	)
	if err != nil {
		resp.Diagnostics.
			AddError("Client Error",
				fmt.Sprintf("Unable to update Azure integration, got error: %s", err),
			)
		return
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *integrationAzureResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data integrationAzureResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Do GraphQL request to API to update the resource.
	_, err := r.client.DeleteIntegration(ctx, data.Mrn.ValueString())
	if err != nil {
		resp.Diagnostics.
			AddError("Client Error",
				fmt.Sprintf("Unable to delete Azure integration, got error: %s", err),
			)
		return
	}
}

func (r *integrationAzureResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	integration, ok := r.client.ImportIntegration(ctx, req, resp)
	if !ok {
		return
	}

	allowList := ConvertListValue(integration.ConfigurationOptions.AzureConfigurationOptions.SubscriptionsWhitelist)
	denyList := ConvertListValue(integration.ConfigurationOptions.AzureConfigurationOptions.SubscriptionsBlacklist)

	model := integrationAzureResourceModel{
		SpaceID:               types.StringValue(integration.SpaceID()),
		Mrn:                   types.StringValue(integration.Mrn),
		Name:                  types.StringValue(integration.Name),
		ClientId:              types.StringValue(integration.ConfigurationOptions.AzureConfigurationOptions.ClientId),
		TenantId:              types.StringValue(integration.ConfigurationOptions.AzureConfigurationOptions.TenantId),
		SubscriptionAllowList: allowList,
		SubscriptionDenyList:  denyList,
		Credential: integrationAzureCredentialModel{
			PEMFile: types.StringPointerValue(nil),
		},
		ScanVms: types.BoolValue(integration.ConfigurationOptions.AzureConfigurationOptions.ScanVms),
	}

	resp.State.Set(ctx, &model)
}
