package provider

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	mondoov1 "go.mondoo.com/mondoo-go"
	"gopkg.in/yaml.v2"
)

var _ resource.Resource = (*customFrameworkResource)(nil)

func NewCustomFrameworkResource() resource.Resource {
	return &customFrameworkResource{}
}

type customFrameworkResource struct {
	client *ExtendedGqlClient
}

type customFrameworkResourceModel struct {
	// scope
	SpaceId types.String `tfsdk:"space_id"`

	// resource details
	Mrn     types.String `tfsdk:"mrn"`
	DataUrl types.String `tfsdk:"data_url"`
}

func (r *customFrameworkResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_custom_framework"
}

type Framework struct {
	UID  string `yaml:"uid"`
	Name string `yaml:"name"`
}

type Config struct {
	Frameworks []Framework `yaml:"frameworks"`
}

func (r *customFrameworkResource) getFrameworkContent(data customFrameworkResourceModel) ([]byte, string, error) {
	var frameworkData []byte
	var config Config
	if !data.DataUrl.IsNull() {
		// load content from file
		content, err := os.ReadFile(data.DataUrl.ValueString())
		if err != nil {
			return nil, "", err
		}
		frameworkData = content

		// unmarshal the yaml content
		err = yaml.Unmarshal(content, &config)
		if err != nil {
			return nil, "", fmt.Errorf("unable to unmarshal YAML: %w", err)
		}
	}
	return frameworkData, config.Frameworks[0].UID, nil
}

func (r *customFrameworkResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: `Set custom Compliance Frameworks for a Mondoo Space.`,
		Attributes: map[string]schema.Attribute{
			"space_id": schema.StringAttribute{
				MarkdownDescription: "Mondoo Space Identifier.",
				Required:            true,
			},
			"mrn": schema.StringAttribute{
				MarkdownDescription: "Mondoo Resource Name.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"data_url": schema.StringAttribute{
				MarkdownDescription: "URL to the custom Compliance Framework data.",
				Required:            true,
			},
		},
	}
}

func (r *customFrameworkResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *customFrameworkResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data customFrameworkResourceModel

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

	content, uid, err := r.getFrameworkContent(data)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to get Compliance Framework Content, got error: %s", err))
		return
	}

	err = r.client.UploadFramework(ctx, spaceMrn, content)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to upload Compliance Framework, got error: %s", err))
		return
	}

	framework, err := r.client.GetFramework(ctx, spaceMrn, data.SpaceId.ValueString(), uid)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to get Compliance Framework, got error: %s", err))
		return
	}

	data.Mrn = types.StringValue(string(framework.Mrn))

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *customFrameworkResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data customFrameworkResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Read API call logic

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *customFrameworkResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data customFrameworkResourceModel

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

	content, _, err := r.getFrameworkContent(data)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to get Compliance Framework Content, got error: %s", err))
		return
	}

	err = r.client.UploadFramework(ctx, spaceMrn, content)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to upload Compliance Framework, got error: %s", err))
		return
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *customFrameworkResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data customFrameworkResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Do GraphQL request to API to update the resource.
	err := r.client.DeleteFramework(ctx, data.Mrn.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to delete Compliance Framework, got error: %s", err))
		return
	}
}

func (r *customFrameworkResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// resource.ImportStatePassthroughID(ctx, path.Root("mrn"), req, resp)
	mrn := req.ID
	splitMrn := strings.Split(mrn, "/")
	spaceMrn := spacePrefix + splitMrn[len(splitMrn)-3]
	spaceId := splitMrn[len(splitMrn)-3]
	uid := splitMrn[len(splitMrn)-1]

	framework, err := r.client.GetFramework(ctx, spaceMrn, spaceId, uid)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to get Compliance Framework, got error: %s", err))
		return
	}

	model := customFrameworkResourceModel{
		Mrn:     types.StringValue(string(framework.Mrn)),
		DataUrl: types.StringPointerValue(nil),
		SpaceId: types.StringValue(spaceId),
	}

	resp.State.Set(ctx, &model)
}
