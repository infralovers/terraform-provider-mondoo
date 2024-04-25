package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
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
	SpaceId types.String `tfsdk:"space_id"`

	// integration details
	Mrn                    types.String `tfsdk:"mrn"`
	Name                   types.String `tfsdk:"name"`
	ClientId               types.String `tfsdk:"client_id"`
	TenantId               types.String `tfsdk:"tenant_id"`
	SubscriptionsWhitelist types.List   `tfsdk:"subscription_whitelist"`
	SubscriptionsBlacklist types.List   `tfsdk:"subscription_blacklist"`
	ScanVms                types.Bool   `tfsdk:"scan_vms"`

	// credentials
	Credential integrationAzureCredentialModel `tfsdk:"credentials"`
}

type integrationAzureCredentialModel struct {
	PEMFile types.String `tfsdk:"pem_file"`
}

func (r *integrationAzureResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_integration_azure"
}

func (r *integrationAzureResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"space_id": schema.StringAttribute{
				MarkdownDescription: "Mondoo Space Identifier.",
				Required:            true,
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
				Optional:            true,
			},
			"client_id": schema.StringAttribute{
				MarkdownDescription: "Azure Client ID.",
				Required:            true,
			},
			"tenant_id": schema.StringAttribute{
				MarkdownDescription: "Azure Tenant ID.",
				Required:            true,
			},
			"scan_vms": schema.BoolAttribute{
				MarkdownDescription: "Scan VMs.",
				Optional:            true,
			},
			"subscription_whitelist": schema.ListAttribute{
				MarkdownDescription: "List of Azure subscriptions to scan.",
				Optional:            true,
				ElementType:         types.StringType,
			},
			"subscription_blacklist": schema.ListAttribute{
				MarkdownDescription: "List of Azure subscriptions to exclude from scanning.",
				Optional:            true,
				ElementType:         types.StringType,
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

	client, ok := req.ProviderData.(*mondoov1.Client)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *http.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	r.client = &ExtendedGqlClient{client}
}

func (r *integrationAzureResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {

	var data integrationAzureResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Do GraphQL request to API to create the resource.
	spaceMrn := ""
	if data.SpaceId.ValueString() != "" {
		spaceMrn = spacePrefix + data.SpaceId.ValueString()
	}

	var listWhite []mondoov1.String
	whitelist, _ := data.SubscriptionsWhitelist.ToListValue(ctx)
	whitelist.ElementsAs(ctx, &listWhite, true)

	var listBlack []mondoov1.String
	blacklist, _ := data.SubscriptionsBlacklist.ToListValue(ctx)
	blacklist.ElementsAs(ctx, &listBlack, true)

	// Check if both whitelist and blacklist are provided
	if len(listBlack) > 0 && len(listWhite) > 0 {
		resp.Diagnostics.AddError("ConflictingAttributesError", "Both subscription_whitelist and subscription_blacklist cannot be provided simultaneously.")
		return
	}

	integration, err := r.client.CreateIntegration(ctx,
		spaceMrn,
		data.Name.ValueString(),
		mondoov1.ClientIntegrationTypeAzure,
		mondoov1.ClientIntegrationConfigurationInput{
			AzureConfigurationOptions: &mondoov1.AzureConfigurationOptionsInput{
				TenantID:               mondoov1.String(data.TenantId.ValueString()),
				ClientID:               mondoov1.String(data.ClientId.ValueString()),
				SubscriptionsWhitelist: &listWhite,
				SubscriptionsBlacklist: &listBlack,
				ScanVms:                mondoov1.NewBooleanPtr(mondoov1.Boolean(data.ScanVms.ValueBool())),
				Certificate:            mondoov1.NewStringPtr(mondoov1.String(data.Credential.PEMFile.ValueString())),
			},
		})
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to create Azure integration, got error: %s", err))
		return
	}

	// Save space mrn into the Terraform state.
	data.Mrn = types.StringValue(string(integration.Mrn))
	data.Name = types.StringValue(string(integration.Name))
	data.SpaceId = types.StringValue(data.SpaceId.ValueString())

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

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *integrationAzureResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data integrationAzureResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Do GraphQL request to API to update the resource.
	var listWhite []mondoov1.String
	whitelist, _ := data.SubscriptionsWhitelist.ToListValue(ctx)
	whitelist.ElementsAs(ctx, &listWhite, true)

	var listBlack []mondoov1.String
	blacklist, _ := data.SubscriptionsBlacklist.ToListValue(ctx)
	blacklist.ElementsAs(ctx, &listBlack, true)

	opts := mondoov1.ClientIntegrationConfigurationInput{
		AzureConfigurationOptions: &mondoov1.AzureConfigurationOptionsInput{
			TenantID:               mondoov1.String(data.TenantId.ValueString()),
			ClientID:               mondoov1.String(data.ClientId.ValueString()),
			SubscriptionsWhitelist: &listWhite,
			SubscriptionsBlacklist: &listBlack,
			ScanVms:                mondoov1.NewBooleanPtr(mondoov1.Boolean(data.ScanVms.ValueBool())),
			Certificate:            mondoov1.NewStringPtr(mondoov1.String(data.Credential.PEMFile.ValueString())),
		},
	}

	_, err := r.client.UpdateIntegration(ctx, data.Mrn.ValueString(), data.Name.ValueString(), mondoov1.ClientIntegrationTypeAzure, opts)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to update Azure integration, got error: %s", err))
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
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to delete Azure integration, got error: %s", err))
		return
	}
}

func (r *integrationAzureResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("mrn"), req, resp)
}
