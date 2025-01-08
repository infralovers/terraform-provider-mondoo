package provider

import (
	"context"
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	mondoov1 "go.mondoo.com/mondoo-go"
)

var _ resource.Resource = (*integrationCrowdStrikeResource)(nil)

func NewIntegrationCrowdStrikeResource() resource.Resource {
	return &integrationCrowdStrikeResource{}
}

type integrationCrowdStrikeResource struct {
	client *ExtendedGqlClient
}

type integrationCrowdStrikeResourceModel struct {
	// scope
	SpaceID types.String `tfsdk:"space_id"`

	// integration details
	Mrn          types.String `tfsdk:"mrn"`
	Name         types.String `tfsdk:"name"`
	ClientID     types.String `tfsdk:"client_id"`
	BaseURL      types.String `tfsdk:"base_url"`
	CustomerID   types.String `tfsdk:"customer_id"`
	CreateAssets types.Bool   `tfsdk:"create_assets"`

	// credentials
	Credential *integrationCrowdStrikeCredentialModel `tfsdk:"credentials"`
}

type integrationCrowdStrikeCredentialModel struct {
	ClientSecret types.String `tfsdk:"client_secret"`
}

func (m integrationCrowdStrikeResourceModel) GetConfigurationOptions() *mondoov1.CrowdstrikeFalconConfigurationOptionsInput {
	opts := &mondoov1.CrowdstrikeFalconConfigurationOptionsInput{
		ClientID:     mondoov1.NewStringPtr(mondoov1.String(m.ClientID.ValueString())),
		ClientSecret: mondoov1.NewStringPtr(mondoov1.String(m.Credential.ClientSecret.ValueString())),
		Cloud:        mondoov1.NewStringPtr(mondoov1.String(m.BaseURL.ValueString())),
		MemberCID:    mondoov1.NewStringPtr(mondoov1.String(m.CustomerID.ValueString())),
		CreateAssets: mondoov1.NewBooleanPtr(mondoov1.Boolean(m.CreateAssets.ValueBool())),
	}

	return opts
}

func (r *integrationCrowdStrikeResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_integration_crowdstrike"
}

func (r *integrationCrowdStrikeResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "This resource allows you to manage a CrowdStrike integration for importing security findings discovered by the CrowdStrike Falcon Spotlight exposure management tool.",
		Attributes: map[string]schema.Attribute{
			"space_id": schema.StringAttribute{
				MarkdownDescription: "Mondoo space identifier. If there is no space ID, the provider space is used.",
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
				MarkdownDescription: "Client ID for the CrowdStrike API client.",
				Required:            true,
			},
			"base_url": schema.StringAttribute{
				MarkdownDescription: "Base URL for the CrowdStrike API client.",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^https?:\/\/[a-zA-Z0-9\-._~:\/?#[\]@!$&'()*+,;=%]+$`),
						"must be a valid URL",
					),
				},
			},
			"customer_id": schema.StringAttribute{
				MarkdownDescription: "CrowdStrike Customer ID.",
				Required:            true,
			},
			"create_assets": schema.BoolAttribute{
				MarkdownDescription: "Create assets in Mondoo for each CrowdStrike unique finding.",
				Optional:            true,
			},
			"credentials": schema.SingleNestedAttribute{
				Required: true,
				Attributes: map[string]schema.Attribute{
					"client_secret": schema.StringAttribute{
						MarkdownDescription: "The secret of the CrowdStrike API client.",
						Required:            true,
						Sensitive:           true,
					},
				},
			},
		},
	}
}

func (r *integrationCrowdStrikeResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*ExtendedGqlClient)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *http.Client. Got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	r.client = client
}

func (r *integrationCrowdStrikeResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data integrationCrowdStrikeResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Compute and validate the space
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
		mondoov1.ClientIntegrationTypeCrowdstrikeFalcon,
		mondoov1.ClientIntegrationConfigurationInput{
			CrowdstrikeFalconConfigurationOptions: data.GetConfigurationOptions(),
		})
	if err != nil {
		resp.Diagnostics.
			AddError("Client Error",
				fmt.Sprintf("Unable to create CrowdStrike integration. Got error: %s", err),
			)
		return
	}

	// trigger integration to gather results quickly after the first setup
	// NOTE: we ignore the error since the integration state does not depend on it
	_, err = r.client.TriggerAction(ctx, string(integration.Mrn), mondoov1.ActionTypeRunImport)
	if err != nil {
		resp.Diagnostics.
			AddWarning("Client Error",
				fmt.Sprintf("Unable to trigger integration. Got error: %s", err),
			)
	}

	// Save space mrn into the Terraform state.
	data.Mrn = types.StringValue(string(integration.Mrn))
	data.Name = types.StringValue(data.Name.ValueString())
	data.SpaceID = types.StringValue(space.ID())

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *integrationCrowdStrikeResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data integrationCrowdStrikeResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Read API call logic

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *integrationCrowdStrikeResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data integrationCrowdStrikeResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	opts := mondoov1.ClientIntegrationConfigurationInput{
		CrowdstrikeFalconConfigurationOptions: data.GetConfigurationOptions(),
	}
	// Update API call logic
	_, err := r.client.UpdateIntegration(ctx,
		data.Mrn.ValueString(),
		data.Name.ValueString(),
		mondoov1.ClientIntegrationTypeCrowdstrikeFalcon,
		opts,
	)
	if err != nil {
		resp.Diagnostics.
			AddError("Client Error",
				fmt.Sprintf("Unable to update CrowdStrike integration. Got error: %s", err),
			)
		return
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *integrationCrowdStrikeResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data integrationCrowdStrikeResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Delete API call logic
	_, err := r.client.DeleteIntegration(ctx, data.Mrn.ValueString())
	if err != nil {
		resp.Diagnostics.
			AddError("Client Error",
				fmt.Sprintf("Unable to delete CrowdStrike integration. Got error: %s", err),
			)
		return
	}
}

func (r *integrationCrowdStrikeResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	integration, ok := r.client.ImportIntegration(ctx, req, resp)
	if !ok {
		return
	}

	model := integrationCrowdStrikeResourceModel{
		Mrn:          types.StringValue(integration.Mrn),
		Name:         types.StringValue(integration.Name),
		SpaceID:      types.StringValue(integration.SpaceID()),
		ClientID:     types.StringValue(integration.ConfigurationOptions.CrowdstrikeFalconConfigurationOptions.ClientID),
		BaseURL:      types.StringValue(integration.ConfigurationOptions.CrowdstrikeFalconConfigurationOptions.Cloud),
		CustomerID:   types.StringValue(integration.ConfigurationOptions.CrowdstrikeFalconConfigurationOptions.MemberCID),
		CreateAssets: types.BoolValue(integration.ConfigurationOptions.CrowdstrikeFalconConfigurationOptions.CreateAssets),
		Credential: &integrationCrowdStrikeCredentialModel{
			ClientSecret: types.StringPointerValue(nil),
		},
	}

	resp.State.Set(ctx, &model)
}
