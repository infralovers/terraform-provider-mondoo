package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	mondoov1 "go.mondoo.com/mondoo-go"
)

var _ resource.Resource = (*integrationAwsServerlessResource)(nil)

func NewIntegrationAwsServerlessResource() resource.Resource {
	return &integrationAwsServerlessResource{}
}

type integrationAwsServerlessResource struct {
	client *ExtendedGqlClient
}

type integrationAwsServerlessResourceModel struct {
	// scope
	SpaceID types.String `tfsdk:"space_id"`

	// integration details
	Mrn   types.String `tfsdk:"mrn"`
	Name  types.String `tfsdk:"name"`
	Token types.String `tfsdk:"token"`

	Region            types.String                                   `tfsdk:"region"`
	ScanConfiguration integrationAwsServerlessScanConfigurationModel `tfsdk:"scan_configuration"`

	// (Optional.)
	AccountIDs types.List `tfsdk:"account_ids"`
	// (Optional.)
	IsOrganization types.Bool `tfsdk:"is_organization"`

	// (Optional.)
	ConsoleSignInTrigger types.Bool `tfsdk:"console_sign_in_trigger"`
	// (Optional.)
	InstanceStateChangeTrigger types.Bool `tfsdk:"instance_state_change_trigger"`
}

type integrationAwsServerlessScanConfigurationModel struct {
	// (Optional.)
	Ec2Scan types.Bool `tfsdk:"ec2_scan"`
	// (Optional.)
	EcrScan types.Bool `tfsdk:"ecr_scan"`
	// (Optional.)
	EcsScan types.Bool `tfsdk:"ecs_scan"`
	// (Optional.)
	CronScaninHours types.Int64 `tfsdk:"cron_scan_in_hours"`
	// (Optional.)
	Ec2ScanOptions *integrationAwsServerlessEc2ScanModel `tfsdk:"ec2_scan_options"`
	// (Optional.)
	VpcConfiguration *integrationAwsServerlessVPCConfigurationModel `tfsdk:"vpc_configuration"`
}

type integrationAwsServerlessVPCConfigurationModel struct {
	UseMondooVPC types.Bool `tfsdk:"use_mondoo_vpc"`
	// (Optional.)
	CIDR types.String `tfsdk:"cidr_block"`
}

type integrationAwsServerlessEc2ScanModel struct {
	// (Optional.)
	Ssm types.Bool `tfsdk:"ssm"`
	// (Optional.)
	InstanceIdsFilter types.List `tfsdk:"instance_ids_filter"`
	// (Optional.)
	RegionsFilter types.List `tfsdk:"regions_filter"`
	// (Optional.)
	TagsFilter types.Map `tfsdk:"tags_filter"`
	// (Optional.)
	ExcludeInstanceIdsFilter types.List `tfsdk:"exclude_instance_ids_filter"`
	// (Optional.)
	ExcludeRegionsFilter types.List `tfsdk:"exclude_regions_filter"`
	// (Optional.)
	ExcludeTagsFilter types.Map `tfsdk:"exclude_tags_filter"`
	// (Optional.)
	EbsVolumeScan types.Bool `tfsdk:"ebs_volume_scan"`
	// (Optional.)
	EbsScanOptions *integrationAwsServerlessEbsScanModel `tfsdk:"ebs_scan_options"`
	// (Optional.)
	InstanceConnect types.Bool `tfsdk:"instance_connect"`
}

type integrationAwsServerlessEbsScanModel struct {
	// (Optional.)
	TargetInstancesPerScanner types.Int64 `tfsdk:"target_instances_per_scanner"`
	// (Optional.)
	MaxAsgInstances types.Int64 `tfsdk:"max_asg_instances"`
}

func (m integrationAwsServerlessResourceModel) GetConfigurationOptions() *mondoov1.AWSConfigurationOptionsInput {
	var opts *mondoov1.AWSConfigurationOptionsInput
	var eventScanTriggers []*mondoov1.AWSEventPatternInput

	if m.InstanceStateChangeTrigger.ValueBool() && m.ConsoleSignInTrigger.ValueBool() {
		eventScanTriggers = append(eventScanTriggers, &mondoov1.AWSEventPatternInput{
			ScanType:        mondoov1.String("ALL"),
			EventSource:     mondoov1.String("aws.signin"),
			EventDetailType: mondoov1.String("AWS Console Sign In via CloudTrail"),
		})
		eventScanTriggers = append(eventScanTriggers, &mondoov1.AWSEventPatternInput{
			ScanType:        mondoov1.String("ALL"),
			EventSource:     mondoov1.String("aws.ec2"),
			EventDetailType: mondoov1.String("EC2 Instance State-change Notification"),
		})
	} else if m.ConsoleSignInTrigger.ValueBool() && !m.InstanceStateChangeTrigger.ValueBool() {
		eventScanTriggers = append(eventScanTriggers, &mondoov1.AWSEventPatternInput{
			ScanType:        mondoov1.String("ALL"),
			EventSource:     mondoov1.String("aws.signin"),
			EventDetailType: mondoov1.String("AWS Console Sign In via CloudTrail"),
		})
	} else if m.InstanceStateChangeTrigger.ValueBool() && !m.ConsoleSignInTrigger.ValueBool() {
		eventScanTriggers = append(eventScanTriggers, &mondoov1.AWSEventPatternInput{
			ScanType:        mondoov1.String("ALL"),
			EventSource:     mondoov1.String("aws.ec2"),
			EventDetailType: mondoov1.String("EC2 Instance State-change Notification"),
		})
	}

	var instanceIdsFilter []mondoov1.String
	instanceIds, _ := m.ScanConfiguration.Ec2ScanOptions.InstanceIdsFilter.ToListValue(context.Background())
	instanceIds.ElementsAs(context.Background(), &instanceIdsFilter, true)

	var regionsFilter []mondoov1.String
	regions, _ := m.ScanConfiguration.Ec2ScanOptions.RegionsFilter.ToListValue(context.Background())
	regions.ElementsAs(context.Background(), &regionsFilter, true)

	var tagsFilter mondoov1.Map
	tags, _ := m.ScanConfiguration.Ec2ScanOptions.TagsFilter.ToMapValue(context.Background())
	tags.ElementsAs(context.Background(), &tagsFilter, true)

	var excludeInstanceIdsFilter []mondoov1.String
	excludeInstanceIds, _ := m.ScanConfiguration.Ec2ScanOptions.ExcludeInstanceIdsFilter.ToListValue(context.Background())
	excludeInstanceIds.ElementsAs(context.Background(), &excludeInstanceIdsFilter, true)

	var excludeRegionsFilter []mondoov1.String
	excludeRegions, _ := m.ScanConfiguration.Ec2ScanOptions.ExcludeRegionsFilter.ToListValue(context.Background())
	excludeRegions.ElementsAs(context.Background(), &excludeRegionsFilter, true)

	var excludeTagsFilter mondoov1.Map
	excludeTags, _ := m.ScanConfiguration.Ec2ScanOptions.ExcludeTagsFilter.ToMapValue(context.Background())
	excludeTags.ElementsAs(context.Background(), &excludeTagsFilter, true)

	var accountIDs []mondoov1.String
	accountIds, _ := m.AccountIDs.ToListValue(context.Background())
	accountIds.ElementsAs(context.Background(), &accountIDs, true)
	opts = &mondoov1.AWSConfigurationOptionsInput{
		Region:         mondoov1.String(m.Region.ValueString()),
		IsOrganization: mondoov1.NewBooleanPtr(mondoov1.Boolean(m.IsOrganization.ValueBool())),
		AccountIDs:     &accountIDs,
		ScanConfiguration: mondoov1.ScanConfigurationInput{
			Ec2Scan:           mondoov1.NewBooleanPtr(mondoov1.Boolean(m.ScanConfiguration.Ec2Scan.ValueBool())),
			EcrScan:           mondoov1.NewBooleanPtr(mondoov1.Boolean(m.ScanConfiguration.EcrScan.ValueBool())),
			EcsScan:           mondoov1.NewBooleanPtr(mondoov1.Boolean(m.ScanConfiguration.EcsScan.ValueBool())),
			CronScaninHours:   mondoov1.NewIntPtr(mondoov1.Int(m.ScanConfiguration.CronScaninHours.ValueInt64())),
			EventScanTriggers: &eventScanTriggers,
			Ec2ScanOptions: &mondoov1.Ec2ScanOptionsInput{
				Ssm:                       mondoov1.NewBooleanPtr(mondoov1.Boolean(m.ScanConfiguration.Ec2ScanOptions.Ssm.ValueBool())),
				InstanceIDsFilter:         &instanceIdsFilter,
				RegionsFilter:             &regionsFilter,
				TagsFilter:                &tagsFilter,
				ExcludedInstanceIDsFilter: &excludeInstanceIdsFilter,
				ExcludedRegionsFilter:     &excludeRegionsFilter,
				ExcludedTagsFilter:        &excludeTagsFilter,
				EbsScanOptions: &mondoov1.EbsScanOptionsInput{
					TargetInstancesPerScanner: mondoov1.NewIntPtr(mondoov1.Int(m.ScanConfiguration.Ec2ScanOptions.EbsScanOptions.TargetInstancesPerScanner.ValueInt64())),
					MaxAsgInstances:           mondoov1.NewIntPtr(mondoov1.Int(m.ScanConfiguration.Ec2ScanOptions.EbsScanOptions.MaxAsgInstances.ValueInt64())),
				},
				EbsVolumeScan:   mondoov1.NewBooleanPtr(mondoov1.Boolean(m.ScanConfiguration.Ec2ScanOptions.EbsVolumeScan.ValueBool())),
				InstanceConnect: mondoov1.NewBooleanPtr(mondoov1.Boolean(m.ScanConfiguration.Ec2ScanOptions.InstanceConnect.ValueBool())),
			},
		},
	}

	if m.ScanConfiguration.VpcConfiguration != nil {
		useMondooVPC := m.ScanConfiguration.VpcConfiguration.UseMondooVPC.ValueBool()
		opts.ScanConfiguration.VpcConfiguration = &mondoov1.VPCConfigurationInput{
			UseMondooVPC:  mondoov1.NewBooleanPtr(mondoov1.Boolean(useMondooVPC)),
			UseDefaultVPC: mondoov1.NewBooleanPtr(mondoov1.Boolean(!useMondooVPC)),
			CIDR:          mondoov1.NewStringPtr(mondoov1.String(m.ScanConfiguration.VpcConfiguration.CIDR.ValueString())),
		}
	}

	return opts
}

func (r *integrationAwsServerlessResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_integration_aws_serverless"
}

func (r *integrationAwsServerlessResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: `Continuously scan AWS organization and accounts for misconfigurations and vulnerabilities.`,
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
			"token": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Integration token",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Name of the integration.",
				Required:            true,
			},
			"region": schema.StringAttribute{
				MarkdownDescription: "AWS region.",
				Required:            true,
			},
			"console_sign_in_trigger": schema.BoolAttribute{
				MarkdownDescription: "Enable console sign in trigger.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"instance_state_change_trigger": schema.BoolAttribute{
				MarkdownDescription: "Enable instance state change trigger.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"scan_configuration": schema.SingleNestedAttribute{
				Required: true,
				Attributes: map[string]schema.Attribute{
					"ec2_scan": schema.BoolAttribute{
						MarkdownDescription: "Enable EC2 scan.",
						Optional:            true,
						Computed:            true,
						Default:             booldefault.StaticBool(false),
					},
					"ecr_scan": schema.BoolAttribute{
						MarkdownDescription: "Enable ECR scan.",
						Optional:            true,
						Computed:            true,
						Default:             booldefault.StaticBool(false),
					},
					"ecs_scan": schema.BoolAttribute{
						MarkdownDescription: "Enable ECS scan.",
						Optional:            true,
						Computed:            true,
						Default:             booldefault.StaticBool(false),
					},
					"cron_scan_in_hours": schema.Int64Attribute{
						MarkdownDescription: "Cron scan in hours.",
						Optional:            true,
						Computed:            true,
						Default:             int64default.StaticInt64(0),
					},
					"vpc_configuration": schema.SingleNestedAttribute{
						Optional: true,
						Computed: true,
						Default: objectdefault.StaticValue(types.ObjectValueMust(map[string]attr.Type{
							"use_mondoo_vpc": types.BoolType,
							"cidr_block":     types.StringType,
						}, map[string]attr.Value{
							"use_mondoo_vpc": types.BoolValue(false),
							"cidr_block":     types.StringValue("10.0.0.0/24"),
						})),
						Attributes: map[string]schema.Attribute{
							"use_mondoo_vpc": schema.BoolAttribute{
								MarkdownDescription: "Use Mondoo VPC.",
								Optional:            true,
								Computed:            true,
								Default:             booldefault.StaticBool(false),
							},
							"cidr_block": schema.StringAttribute{
								MarkdownDescription: "CIDR block for the Mondoo VPC.",
								Optional:            true,
								Computed:            true,
								Default:             stringdefault.StaticString("10.0.0.0/24"),
							},
						},
					},
					"ec2_scan_options": schema.SingleNestedAttribute{
						Optional: true, // Should be optional
						Computed: true,
						Default: objectdefault.StaticValue(types.ObjectValueMust(map[string]attr.Type{
							"ssm":                         types.BoolType,
							"instance_ids_filter":         types.ListType{ElemType: types.StringType},
							"regions_filter":              types.ListType{ElemType: types.StringType},
							"tags_filter":                 types.MapType{ElemType: types.StringType},
							"exclude_instance_ids_filter": types.ListType{ElemType: types.StringType},
							"exclude_regions_filter":      types.ListType{ElemType: types.StringType},
							"exclude_tags_filter":         types.MapType{ElemType: types.StringType},
							"ebs_volume_scan":             types.BoolType,
							"ebs_scan_options": types.ObjectType{
								AttrTypes: map[string]attr.Type{
									"target_instances_per_scanner": types.Int64Type,
									"max_asg_instances":            types.Int64Type,
								},
							},
							"instance_connect": types.BoolType,
						}, map[string]attr.Value{
							"ssm":                         types.BoolValue(false),
							"instance_ids_filter":         types.ListValueMust(types.StringType, []attr.Value{}),
							"regions_filter":              types.ListValueMust(types.StringType, []attr.Value{}),
							"tags_filter":                 types.MapValueMust(types.StringType, make(map[string]attr.Value)),
							"exclude_instance_ids_filter": types.ListValueMust(types.StringType, []attr.Value{}),
							"exclude_regions_filter":      types.ListValueMust(types.StringType, []attr.Value{}),
							"exclude_tags_filter":         types.MapValueMust(types.StringType, make(map[string]attr.Value)),
							"ebs_volume_scan":             types.BoolValue(false),
							"ebs_scan_options": types.ObjectValueMust(map[string]attr.Type{
								"target_instances_per_scanner": types.Int64Type,
								"max_asg_instances":            types.Int64Type,
							}, map[string]attr.Value{
								"target_instances_per_scanner": types.Int64Value(0),
								"max_asg_instances":            types.Int64Value(0),
							}),
							"instance_connect": types.BoolValue(false),
						})),
						Attributes: map[string]schema.Attribute{
							"ssm": schema.BoolAttribute{
								MarkdownDescription: "Enable SSM.",
								Optional:            true,
								Computed:            true,
								Default:             booldefault.StaticBool(false),
							},
							"instance_ids_filter": schema.ListAttribute{
								MarkdownDescription: "List of instance IDs filter.",
								Optional:            true,
								Computed:            true,
								Default:             listdefault.StaticValue(types.ListValueMust(types.StringType, []attr.Value{})),
								ElementType:         types.StringType,
							},
							"regions_filter": schema.ListAttribute{
								MarkdownDescription: "List of regions filter.",
								Optional:            true,
								Computed:            true,
								Default:             listdefault.StaticValue(types.ListValueMust(types.StringType, []attr.Value{})),
								ElementType:         types.StringType,
							},
							"tags_filter": schema.MapAttribute{
								MarkdownDescription: "Tags filter.",
								Optional:            true,
								Computed:            true,
								Default:             mapdefault.StaticValue(types.MapValueMust(types.StringType, make(map[string]attr.Value))),
								ElementType:         types.StringType,
							},
							"exclude_instance_ids_filter": schema.ListAttribute{
								MarkdownDescription: "List of instance IDs to exclude.",
								Optional:            true,
								Computed:            true,
								Default:             listdefault.StaticValue(types.ListValueMust(types.StringType, []attr.Value{})),
								ElementType:         types.StringType,
							},
							"exclude_regions_filter": schema.ListAttribute{
								MarkdownDescription: "List of regions to exclude.",
								Optional:            true,
								Computed:            true,
								Default:             listdefault.StaticValue(types.ListValueMust(types.StringType, []attr.Value{})),
								ElementType:         types.StringType,
							},
							"exclude_tags_filter": schema.MapAttribute{
								MarkdownDescription: "Excluded Tags filter.",
								Optional:            true,
								Computed:            true,
								Default:             mapdefault.StaticValue(types.MapValueMust(types.StringType, make(map[string]attr.Value))),
								ElementType:         types.StringType,
							},
							"ebs_volume_scan": schema.BoolAttribute{
								MarkdownDescription: "Enable EBS volume scan.",
								Optional:            true,
								Computed:            true,
								Default:             booldefault.StaticBool(false),
							},
							"ebs_scan_options": schema.SingleNestedAttribute{
								Optional: true,
								Computed: true,
								Default: objectdefault.StaticValue(types.ObjectValueMust(map[string]attr.Type{
									"target_instances_per_scanner": types.Int64Type,
									"max_asg_instances":            types.Int64Type,
								}, map[string]attr.Value{
									"target_instances_per_scanner": types.Int64Value(0),
									"max_asg_instances":            types.Int64Value(0),
								})),
								DeprecationMessage: "This field is deprecated and will be removed in the future.",
								Attributes: map[string]schema.Attribute{
									"target_instances_per_scanner": schema.Int64Attribute{
										MarkdownDescription: "Target instances per scanner.",
										Optional:            true,
										Computed:            true,
										Default:             int64default.StaticInt64(0),
										DeprecationMessage:  "This field is deprecated and will be removed in the future.",
									},
									"max_asg_instances": schema.Int64Attribute{
										MarkdownDescription: "Max ASG instances.",
										Optional:            true,
										Computed:            true,
										Default:             int64default.StaticInt64(0),
										DeprecationMessage:  "This field is deprecated and will be removed in the future.",
									},
								},
							},
							"instance_connect": schema.BoolAttribute{
								MarkdownDescription: "Enable instance connect.",
								Optional:            true,
								Computed:            true,
								Default:             booldefault.StaticBool(false),
							},
						},
					},
				},
			},
			"account_ids": schema.ListAttribute{
				MarkdownDescription: "List of AWS account IDs.",
				Optional:            true,
				Computed:            true,
				ElementType:         types.StringType,
				Default:             listdefault.StaticValue(types.ListValueMust(types.StringType, []attr.Value{})),
			},
			"is_organization": schema.BoolAttribute{
				MarkdownDescription: "Is organization.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
		},
	}
}

func (r integrationAwsServerlessResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data integrationAwsServerlessResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// user has provided mondoo vpc only
	if mondooVpc := data.ScanConfiguration.VpcConfiguration != nil && data.ScanConfiguration.VpcConfiguration.UseMondooVPC.ValueBool(); mondooVpc {
		if cidr := data.ScanConfiguration.VpcConfiguration.CIDR.ValueString(); cidr == "" {
			resp.Diagnostics.AddError(
				"MissingAttributeError",
				"Attribute cidr_block must not be empty when use_mondoo_vpc is set to true.",
			)
		}
	}
}

func (r *integrationAwsServerlessResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *integrationAwsServerlessResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data integrationAwsServerlessResourceModel

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
	var accountIDs []mondoov1.String
	accountIds, _ := data.AccountIDs.ToListValue(context.Background())
	accountIds.ElementsAs(context.Background(), &accountIDs, true)

	// Check if both whitelist and blacklist are provided
	if len(accountIDs) > 0 && data.IsOrganization.ValueBool() {
		resp.Diagnostics.
			AddError("ConflictingAttributesError",
				"Cannot install CloudFormation Stack to both AWS organization and accounts.",
			)
		return
	}

	tflog.Debug(ctx, "Creating integration")
	integration, err := r.client.CreateIntegration(ctx,
		space.MRN(),
		data.Name.ValueString(),
		mondoov1.ClientIntegrationTypeAws,
		mondoov1.ClientIntegrationConfigurationInput{
			AwsConfigurationOptions: data.GetConfigurationOptions(),
		})
	if err != nil {
		resp.Diagnostics.
			AddError("Client Error",
				fmt.Sprintf("Unable to create AWS integration, got error: %s", err),
			)
		return
	}

	// Save space mrn into the Terraform state.
	data.Mrn = types.StringValue(string(integration.Mrn))
	data.Name = types.StringValue(string(integration.Name))
	data.Token = types.StringValue(string(integration.Token))
	data.SpaceID = types.StringValue(space.ID())

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *integrationAwsServerlessResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data integrationAwsServerlessResourceModel

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

	model := integrationAwsServerlessResourceModel{
		Mrn:                        types.StringValue(integration.Mrn),
		Name:                       types.StringValue(integration.Name),
		SpaceID:                    types.StringValue(integration.SpaceID()),
		Token:                      types.StringValue(data.Token.ValueString()),
		ConsoleSignInTrigger:       types.BoolValue(false),
		InstanceStateChangeTrigger: types.BoolValue(false),
		Region:                     types.StringValue(integration.ConfigurationOptions.AWSConfigurationOptions.Region),
		AccountIDs:                 ConvertListValue(integration.ConfigurationOptions.AWSConfigurationOptions.AccountIDs),
		IsOrganization:             types.BoolValue(integration.ConfigurationOptions.AWSConfigurationOptions.IsOrganization),
		ScanConfiguration: integrationAwsServerlessScanConfigurationModel{
			Ec2Scan:         types.BoolValue(integration.ConfigurationOptions.AWSConfigurationOptions.ScanConfiguration.Ec2Scan),
			EcrScan:         types.BoolValue(integration.ConfigurationOptions.AWSConfigurationOptions.ScanConfiguration.EcrScan),
			EcsScan:         types.BoolValue(integration.ConfigurationOptions.AWSConfigurationOptions.ScanConfiguration.EcsScan),
			CronScaninHours: types.Int64Value(integration.ConfigurationOptions.AWSConfigurationOptions.ScanConfiguration.CronScaninHours),
			Ec2ScanOptions: &integrationAwsServerlessEc2ScanModel{
				Ssm:                      types.BoolValue(integration.ConfigurationOptions.AWSConfigurationOptions.ScanConfiguration.Ec2ScanOptions.Ssm),
				InstanceIdsFilter:        ConvertListValue(integration.ConfigurationOptions.AWSConfigurationOptions.ScanConfiguration.Ec2ScanOptions.InstanceIDsFilter),
				RegionsFilter:            ConvertListValue(integration.ConfigurationOptions.AWSConfigurationOptions.ScanConfiguration.Ec2ScanOptions.RegionsFilter),
				TagsFilter:               ConvertMapValue(integration.ConfigurationOptions.AWSConfigurationOptions.ScanConfiguration.Ec2ScanOptions.TagsFilter),
				ExcludeInstanceIdsFilter: ConvertListValue(integration.ConfigurationOptions.AWSConfigurationOptions.ScanConfiguration.Ec2ScanOptions.ExcludedInstanceIDsFilter),
				ExcludeRegionsFilter:     ConvertListValue(integration.ConfigurationOptions.AWSConfigurationOptions.ScanConfiguration.Ec2ScanOptions.ExcludedRegionsFilter),
				ExcludeTagsFilter:        ConvertMapValue(integration.ConfigurationOptions.AWSConfigurationOptions.ScanConfiguration.Ec2ScanOptions.ExcludedTagsFilter),
				EbsVolumeScan:            types.BoolValue(integration.ConfigurationOptions.AWSConfigurationOptions.ScanConfiguration.Ec2ScanOptions.EbsVolumeScan),
				EbsScanOptions: &integrationAwsServerlessEbsScanModel{
					TargetInstancesPerScanner: types.Int64Value(integration.ConfigurationOptions.AWSConfigurationOptions.ScanConfiguration.Ec2ScanOptions.EbsScanOptions.TargetInstancesPerScanner),
					MaxAsgInstances:           types.Int64Value(integration.ConfigurationOptions.AWSConfigurationOptions.ScanConfiguration.Ec2ScanOptions.EbsScanOptions.MaxAsgInstances),
				},
				InstanceConnect: types.BoolValue(integration.ConfigurationOptions.AWSConfigurationOptions.ScanConfiguration.Ec2ScanOptions.InstanceConnect),
			},
			VpcConfiguration: &integrationAwsServerlessVPCConfigurationModel{
				UseMondooVPC: types.BoolValue(integration.ConfigurationOptions.AWSConfigurationOptions.ScanConfiguration.VpcConfiguration.UseMondooVPC),
				CIDR:         types.StringValue(integration.ConfigurationOptions.AWSConfigurationOptions.ScanConfiguration.VpcConfiguration.CIDR),
			},
		},
	}

	if integration.ConfigurationOptions.AWSConfigurationOptions.ScanConfiguration.EventScanTriggers != nil {
		eventScanTriggers := integration.ConfigurationOptions.AWSConfigurationOptions.ScanConfiguration.EventScanTriggers
		for _, item := range eventScanTriggers {
			if item.EventSource == "aws.signin" {
				model.ConsoleSignInTrigger = types.BoolValue(true)
			}
			if item.EventSource == "aws.ec2" {
				model.InstanceStateChangeTrigger = types.BoolValue(true)
			}
		}
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

func (r *integrationAwsServerlessResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data integrationAwsServerlessResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	var accountIDs []mondoov1.String
	accountIds, _ := data.AccountIDs.ToListValue(context.Background())
	accountIds.ElementsAs(context.Background(), &accountIDs, true)

	// Check if both whitelist and blacklist are provided
	if len(accountIDs) > 0 && data.IsOrganization.ValueBool() {
		resp.Diagnostics.
			AddError("ConflictingAttributesError",
				"Cannot install CloudFormation Stack to both AWS organization and accounts.",
			)
		return
	}

	if resp.Diagnostics.HasError() {
		return
	}

	// Do GraphQL request to API to update the resource.
	opts := mondoov1.ClientIntegrationConfigurationInput{
		AwsConfigurationOptions: data.GetConfigurationOptions(),
	}

	_, err := r.client.UpdateIntegration(ctx,
		data.Mrn.ValueString(),
		data.Name.ValueString(),
		mondoov1.ClientIntegrationTypeAws,
		opts,
	)
	if err != nil {
		resp.Diagnostics.
			AddError("Client Error",
				fmt.Sprintf("Unable to update AWS integration, got error: %s", err),
			)
		return
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *integrationAwsServerlessResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data integrationAwsServerlessResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.DeleteIntegration(ctx, data.Mrn.ValueString())
	if err != nil {
		resp.Diagnostics.
			AddError("Client Error",
				fmt.Sprintf(
					"Unable to delete AWS serverless integration '%s', got error: %s",
					data.Mrn.ValueString(), err.Error(),
				),
			)
		return
	}
}

func (r *integrationAwsServerlessResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	integration, ok := r.client.ImportIntegration(ctx, req, resp)
	if !ok {
		return
	}

	model := integrationAwsServerlessResourceModel{
		Mrn:     types.StringValue(integration.Mrn),
		Name:    types.StringValue(integration.Name),
		SpaceID: types.StringValue(integration.SpaceID()),
	}

	resp.State.Set(ctx, &model)
}
