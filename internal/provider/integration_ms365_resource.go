package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	mondoov1 "go.mondoo.com/mondoo-go"
)

var _ resource.Resource = (*integrationMs365Resource)(nil)

func NewIntegrationMs365Resource() resource.Resource {
	return &integrationMs365Resource{}
}

type integrationMs365Resource struct {
	client *ExtendedGqlClient
}

type integrationMs365ResourceModel struct {
	// scope
	SpaceId types.String `tfsdk:"space_id"`

	// integration details
	Mrn      types.String `tfsdk:"mrn"`
	Name     types.String `tfsdk:"name"`
	ClientId types.String `tfsdk:"client_id"`
	TenantId types.String `tfsdk:"tenant_id"`

	// credentials
	Credential integrationMs365CredentialModel `tfsdk:"credentials"`
}

type integrationMs365CredentialModel struct {
	PEMFile types.String `tfsdk:"pem_file"`
}

func (r *integrationMs365Resource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_integration_ms365"
}

func (r *integrationMs365Resource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: `Continuously monitor your Microsoft 365 resources for misconfigurations and vulnerabilities. See [Mondoo documentation](https://mondoo.com/docs/platform/infra/saas/ms365/ms365-auto/) for more details.`,
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
				Required:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(250),
				},
			},
			"client_id": schema.StringAttribute{
				MarkdownDescription: "Azure Client ID.",
				Required:            true,
			},
			"tenant_id": schema.StringAttribute{
				MarkdownDescription: "Azure Tenant ID.",
				Required:            true,
			},
			"credentials": schema.SingleNestedAttribute{
				Required: true,
				Attributes: map[string]schema.Attribute{
					"pem_file": schema.StringAttribute{
						MarkdownDescription: "PEM file for Ms365 integration.",
						Required:            true,
						Sensitive:           true,
					},
				},
			},
		},
	}
}

func (r *integrationMs365Resource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *integrationMs365Resource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data integrationMs365ResourceModel

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

	integration, err := r.client.CreateIntegration(ctx,
		spaceMrn,
		data.Name.ValueString(),
		mondoov1.ClientIntegrationTypeMs365,
		mondoov1.ClientIntegrationConfigurationInput{
			Ms365ConfigurationOptions: &mondoov1.Ms365ConfigurationOptionsInput{
				TenantID:    mondoov1.String(data.TenantId.ValueString()),
				ClientID:    mondoov1.String(data.ClientId.ValueString()),
				Certificate: mondoov1.NewStringPtr(mondoov1.String(data.Credential.PEMFile.ValueString())),
			},
		})
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to create MS365 integration, got error: %s", err))
		return
	}

	// trigger integration to gather results quickly after the first setup
	// NOTE: we ignore the error since the integration state does not depend on it
	_, err = r.client.TriggerAction(ctx, string(integration.Mrn), mondoov1.ActionTypeRunScan)
	if err != nil {
		resp.Diagnostics.AddWarning("Client Error", fmt.Sprintf("Unable to trigger integration, got error: %s", err))
		return
	}

	// Save space mrn into the Terraform state.
	data.Mrn = types.StringValue(string(integration.Mrn))
	data.Name = types.StringValue(string(integration.Name))
	data.SpaceId = types.StringValue(data.SpaceId.ValueString())

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *integrationMs365Resource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data integrationMs365ResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Read API call logic

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *integrationMs365Resource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data integrationMs365ResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Do GraphQL request to API to update the resource.
	opts := mondoov1.ClientIntegrationConfigurationInput{
		Ms365ConfigurationOptions: &mondoov1.Ms365ConfigurationOptionsInput{
			TenantID:    mondoov1.String(data.TenantId.ValueString()),
			ClientID:    mondoov1.String(data.ClientId.ValueString()),
			Certificate: mondoov1.NewStringPtr(mondoov1.String(data.Credential.PEMFile.ValueString())),
		},
	}

	_, err := r.client.UpdateIntegration(ctx, data.Mrn.ValueString(), data.Name.ValueString(), mondoov1.ClientIntegrationTypeMs365, opts)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to update Ms365 integration, got error: %s", err))
		return
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *integrationMs365Resource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data integrationMs365ResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Do GraphQL request to API to update the resource.
	_, err := r.client.DeleteIntegration(ctx, data.Mrn.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to delete Ms365 integration, got error: %s", err))
		return
	}
}

func (r *integrationMs365Resource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	mrn := req.ID
	integration, err := r.client.GetClientIntegration(ctx, mrn)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to get Ms365 integration, got error: %s", err))
		return
	}

	model := integrationMs365ResourceModel{
		Mrn:      types.StringValue(string(integration.Mrn)),
		Name:     types.StringValue(string(integration.Name)),
		SpaceId:  types.StringValue(strings.Split(integration.Mrn, "/")[len(strings.Split(integration.Mrn, "/"))-3]),
		TenantId: types.StringValue(integration.ConfigurationOptions.Ms365ConfigurationOptions.TenantId),
		ClientId: types.StringValue(integration.ConfigurationOptions.Ms365ConfigurationOptions.ClientId),
		Credential: integrationMs365CredentialModel{
			PEMFile: types.StringPointerValue(nil),
		},
	}

	resp.State.SetAttribute(ctx, path.Root("space_id"), model.SpaceId)
	resp.State.SetAttribute(ctx, path.Root("mrn"), model.Mrn)
	resp.State.SetAttribute(ctx, path.Root("name"), model.Name)
	resp.State.SetAttribute(ctx, path.Root("tenant_id"), model.TenantId)
	resp.State.SetAttribute(ctx, path.Root("client_id"), model.ClientId)
	resp.State.SetAttribute(ctx, path.Root("credentials"), model.Credential)
}
