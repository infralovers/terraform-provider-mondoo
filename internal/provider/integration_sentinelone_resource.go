package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	mondoov1 "go.mondoo.com/mondoo-go"
)

var _ resource.Resource = (*integrationSentinelOneResource)(nil)

func NewIntegrationSentinelOneResource() resource.Resource {
	return &integrationSentinelOneResource{}
}

type integrationSentinelOneResource struct {
	client *ExtendedGqlClient
}

type integrationSentinelOneResourceModel struct {
	// scope
	SpaceID types.String `tfsdk:"space_id"`

	// integration details
	Mrn     types.String `tfsdk:"mrn"`
	Name    types.String `tfsdk:"name"`
	Host    types.String `tfsdk:"host"`
	Account types.String `tfsdk:"account"`

	// credentials
	Credential *integrationSentinelOneCredentialsModel `tfsdk:"credentials"`
}

type integrationSentinelOneCredentialsModel struct {
	PEMFile      types.String `tfsdk:"pem_file"`
	ClientSecret types.String `tfsdk:"client_secret"`
}

func (m integrationSentinelOneResourceModel) GetConfigurationOptions() *mondoov1.SentinelOneConfigurationOptionsInput {

	opts := &mondoov1.SentinelOneConfigurationOptionsInput{}
	if m.Credential.PEMFile.ValueString() != "" {
		opts = &mondoov1.SentinelOneConfigurationOptionsInput{
			Host:        mondoov1.String(m.Host.ValueString()),
			Account:     mondoov1.String(m.Account.ValueString()),
			Certificate: mondoov1.NewStringPtr(mondoov1.String(m.Credential.PEMFile.ValueString())),
		}
	} else {
		opts = &mondoov1.SentinelOneConfigurationOptionsInput{
			Host:         mondoov1.String(m.Host.ValueString()),
			Account:      mondoov1.String(m.Account.ValueString()),
			ClientSecret: mondoov1.NewStringPtr(mondoov1.String(m.Credential.ClientSecret.ValueString())),
		}
	}

	return opts
}

func (r *integrationSentinelOneResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_integration_sentinelone"
}

func (v ExclusiveAttributesValidator) ValidateObject(ctx context.Context, req validator.ObjectRequest, resp *validator.ObjectResponse) {
	v.Validate(ctx, req, resp)
}

// ExclusiveAttributesValidator ensures that only one of two optional attributes is set.
type ExclusiveAttributesValidator struct {
	Attr1 string
	Attr2 string
}

// Validate performs the validation.
func (v ExclusiveAttributesValidator) Validate(ctx context.Context, req validator.ObjectRequest, resp *validator.ObjectResponse) {
	var attr1Val, attr2Val types.String

	if diags := req.Config.GetAttribute(ctx, path.Root("credentials").AtName(v.Attr1), &attr1Val); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
	attr1Exists := !attr1Val.IsNull()

	if diags := req.Config.GetAttribute(ctx, path.Root("credentials").AtName(v.Attr2), &attr2Val); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
	attr2Exists := !attr2Val.IsNull()

	if attr1Exists && !attr1Val.IsNull() && attr2Exists && !attr2Val.IsNull() {
		resp.Diagnostics.AddAttributeError(
			path.Root("credentials").AtName(v.Attr1),
			"Conflicting Attributes",
			fmt.Sprintf("Only one of '%s' or '%s' can be provided.", v.Attr1, v.Attr2),
		)
	} else if !attr1Exists && !attr2Exists {
		resp.Diagnostics.AddAttributeError(
			path.Root(v.Attr1),
			"Missing Required Attribute",
			fmt.Sprintf("One of '%s' or '%s' must be provided.", v.Attr1, v.Attr2),
		)
	}
}

// Description returns a plain-text description of the validator's purpose.
func (v ExclusiveAttributesValidator) Description(ctx context.Context) string {
	return fmt.Sprintf("Ensures only one of '%s' or '%s' is provided.", v.Attr1, v.Attr2)
}

// MarkdownDescription returns a markdown-formatted description of the validator's purpose.
func (v ExclusiveAttributesValidator) MarkdownDescription(ctx context.Context) string {
	return fmt.Sprintf("Ensures only one of '%s' or '%s' is provided.", v.Attr1, v.Attr2)
}

// NewExclusiveAttributesValidator creates an instance of the validator.
func NewExclusiveAttributesValidator(attr1, attr2 string) validator.Object {
	return &ExclusiveAttributesValidator{
		Attr1: attr1,
		Attr2: attr2,
	}
}

func (r *integrationSentinelOneResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Continuously scan Sentinel One subscriptions and resources for misconfigurations and vulnerabilities.",
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
			"host": schema.StringAttribute{
				MarkdownDescription: "Sentinel One host.",
				Required:            true,
			},
			"account": schema.StringAttribute{
				MarkdownDescription: "Sentinel One account.",
				Required:            true,
			},
			"credentials": schema.SingleNestedAttribute{
				Required:            true,
				MarkdownDescription: "Credentials for Sentinel One integration. Remote changes will not be detected.",
				Validators: []validator.Object{
					NewExclusiveAttributesValidator("pem_file", "client_secret"),
				},
				Attributes: map[string]schema.Attribute{
					"pem_file": schema.StringAttribute{
						MarkdownDescription: "PEM file for Sentinel One integration.",
						Optional:            true,
						Sensitive:           true,
					},
					"client_secret": schema.StringAttribute{
						MarkdownDescription: "Client secret for Sentinel One integration.",
						Optional:            true,
						Sensitive:           true,
					},
				},
			},
		},
	}
}

func (r *integrationSentinelOneResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *integrationSentinelOneResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data integrationSentinelOneResourceModel

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
		mondoov1.ClientIntegrationTypeSentinelOne,
		mondoov1.ClientIntegrationConfigurationInput{
			SentinelOneConfigurationOptions: data.GetConfigurationOptions(),
		})
	if err != nil {
		resp.Diagnostics.
			AddError("Client Error",
				fmt.Sprintf("Unable to create SentinelOne integration. Got error: %s", err),
			)
		return
	}

	// trigger integration to gather results quickly after the first setup
	// NOTE: we ignore the error since the integration state does not depend on it
	_, err = r.client.TriggerAction(ctx, string(integration.Mrn), mondoov1.ActionTypeRunImport)
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

func (r *integrationSentinelOneResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data integrationSentinelOneResourceModel

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

	model := integrationSentinelOneResourceModel{
		Mrn:     types.StringValue(integration.Mrn),
		Name:    types.StringValue(integration.Name),
		SpaceID: types.StringValue(integration.SpaceID()),
		Host:    types.StringValue(integration.ConfigurationOptions.SentinelOneConfigurationOptions.Host),
		Account: types.StringValue(integration.ConfigurationOptions.SentinelOneConfigurationOptions.Account),
		Credential: &integrationSentinelOneCredentialsModel{
			PEMFile:      types.StringPointerValue(nil),
			ClientSecret: types.StringPointerValue(nil),
		},
	}

	if data.Credential.PEMFile.ValueString() != "" {
		model.Credential.PEMFile = types.StringValue(data.Credential.PEMFile.ValueString())
	}
	if data.Credential.ClientSecret.ValueString() != "" {
		model.Credential.ClientSecret = types.StringValue(data.Credential.ClientSecret.ValueString())
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

func (r *integrationSentinelOneResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data integrationSentinelOneResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Do GraphQL request to API to update the resource.
	opts := mondoov1.ClientIntegrationConfigurationInput{
		SentinelOneConfigurationOptions: data.GetConfigurationOptions(),
	}

	_, err := r.client.UpdateIntegration(ctx,
		data.Mrn.ValueString(),
		data.Name.ValueString(),
		mondoov1.ClientIntegrationTypeSentinelOne,
		opts,
	)
	if err != nil {
		resp.Diagnostics.
			AddError("Client Error",
				fmt.Sprintf("Unable to update SentinelOne integration, got error: %s", err),
			)
		return
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *integrationSentinelOneResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data integrationSentinelOneResourceModel

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
				fmt.Sprintf("Unable to delete SentinelOne integration, got error: %s", err),
			)
		return
	}
}

func (r *integrationSentinelOneResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	integration, ok := r.client.ImportIntegration(ctx, req, resp)
	if !ok {
		return
	}

	model := integrationSentinelOneResourceModel{
		Mrn:     types.StringValue(integration.Mrn),
		Name:    types.StringValue(integration.Name),
		SpaceID: types.StringValue(integration.SpaceID()),
		Host:    types.StringValue(integration.ConfigurationOptions.SentinelOneConfigurationOptions.Host),
		Account: types.StringValue(integration.ConfigurationOptions.SentinelOneConfigurationOptions.Account),
		Credential: &integrationSentinelOneCredentialsModel{
			PEMFile:      types.StringPointerValue(nil),
			ClientSecret: types.StringPointerValue(nil),
		},
	}

	resp.State.Set(ctx, &model)
}
