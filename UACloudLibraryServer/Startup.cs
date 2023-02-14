/* ========================================================================
 * Copyright (c) 2005-2021 The OPC Foundation, Inc. All rights reserved.
 *
 * OPC Foundation MIT License 1.00
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * The complete license agreement can be found here:
 * http://opcfoundation.org/License/MIT/1.00/
 * ======================================================================*/

namespace Opc.Ua.Cloud.Library
{
    using System;
    using System.Collections.Generic;
    using System.Data;
    using System.IO;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Amazon.S3;
    using GraphQL.Server.Ui.Playground;
    using HotChocolate.AspNetCore;
    using HotChocolate.Data;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Authentication.AzureAD.UI;
    using Microsoft.AspNetCore.Authentication.Cookies;
    using Microsoft.AspNetCore.Authentication.OpenIdConnect;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.DataProtection;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Identity.UI.Services;
    using Microsoft.AspNetCore.Mvc.Authorization;
    using Microsoft.AspNetCore.Server.Kestrel.Core;
    using Microsoft.EntityFrameworkCore;
    using Microsoft.Extensions.Configuration;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.Hosting;
    using Microsoft.Extensions.Logging;
    using Microsoft.Identity.Web;
    using Microsoft.Identity.Web.UI;
    using Microsoft.OpenApi.Models;
    using Opc.Ua.Cloud.Library.Interfaces;

    public class Startup
    {
        public Startup(IConfiguration configuration, IWebHostEnvironment environment)
        {
            Configuration = configuration;
            Environment = environment;
        }

        public IConfiguration Configuration { get; }

        public IWebHostEnvironment Environment { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews().AddNewtonsoftJson();

            services.AddRazorPages()
#if AZUREAD
                .AddMvcOptions(options =>
                {
                    var policy = new AuthorizationPolicyBuilder()
                                     .AddAuthenticationSchemes(OpenIdConnectDefaults.AuthenticationScheme)
                                     .RequireAuthenticatedUser()
                                     .Build();
                    //options.Filters.Add(new AuthorizeFilter(policy));
                })
                .AddMicrosoftIdentityUI()
#endif
            ;

            // Setup database context for ASP.NetCore Identity Scaffolding
            services.AddDbContext<AppDbContext>(ServiceLifetime.Transient);
#if true // !AZUREAD

            services.AddDefaultIdentity<IdentityUser>(options =>
                    //require confirmation mail if email sender API Key is set
                    options.SignIn.RequireConfirmedAccount = !string.IsNullOrEmpty(Configuration["EmailSenderAPIKey"])
                    )
                .AddRoles<IdentityRole>()
                .AddEntityFrameworkStores<AppDbContext>();

            services.AddScoped<IUserService, UserService>();
#endif
            services.AddTransient<IDatabase, CloudLibDataProvider>();

            if (!string.IsNullOrEmpty(Configuration["UseSendGridEmailSender"]))
            {
                services.AddTransient<IEmailSender, SendGridEmailSender>();
            }
            else
            {
                services.AddTransient<IEmailSender, PostmarkEmailSender>();
            }

            services.AddLogging(builder => builder.AddConsole());

#if AZUREAD

            //#pragma warning disable CS0618 // Type or member is obsolete
            //            services.AddAuthentication(AzureADDefaults.AuthenticationScheme)
            //                .AddAzureAD(options => Configuration.Bind("AzureAdSettings", options));

            //            services.Configure<OpenIdConnectOptions>(AzureADDefaults.OpenIdScheme, options => {
            //                options.SignInScheme = IdentityConstants.ExternalScheme;
            //            });
            //#pragma warning restore CS0618 // Type or member is obsolete


            //services.AddAuthentication()
            //    .AddMicrosoftIdentityWebApp(Configuration, "AzureAdSettings", OpenIdConnectDefaults.AuthenticationScheme, displayName: "Azure AD");

            services.AddAuthentication()
                .AddMicrosoftIdentityWebApp(options => {
                    Configuration.Bind("AzureAdSettings", options);
                },
                cookieOptions => {
                    cookieOptions.Events.OnSignedIn += (ctx) => {
                        return OnSignedIn(ctx);
                    };
                }, displayName: "Azure AD")
                //.EnableTokenAcquisitionToCallDownstreamApi()
                ;


            //services.AddAuthentication("AzureAd")
            //    .AddMicrosoftIdentityWebApi(Configuration, "AzureAdSettings", "AzureAd")
            //    ;
#endif
            //services.AddAuthentication()
            //    .AddCookie("Identity.External", options => {
            //        options.ForwardDefault = "Cookies";
            //    });
            services.AddAuthentication()
                .AddScheme<AuthenticationSchemeOptions, BasicAuthenticationHandler>("BasicAuthentication", null);

            services.AddAuthorization(options => {
                options.AddPolicy("ApprovalPolicy", policy => policy.RequireRole("Administrator"));
                options.AddPolicy("UserAdministrationPolicy", policy => policy.RequireRole("Administrator"));
            });

            //services
            //        .AddOptions()
            //        .PostConfigureAll<OpenIdConnectOptions>(o => {
            //            o.SignInScheme = IdentityConstants.ExternalScheme;
            //            o.ClaimActions.Add(new ClaimMapper());
            //        });

            services.AddSwaggerGen(options => {
                options.SwaggerDoc("v1", new OpenApiInfo {
                    Title = "UA Cloud Library REST Service",
                    Version = "v1",
                    Description = "A REST-full interface to the CESMII & OPC Foundation Cloud Library",
                    Contact = new OpenApiContact {
                        Name = "OPC Foundation",
                        Email = "office@opcfoundation.org",
                        Url = new Uri("https://opcfoundation.org/")
                    }
                });

                options.AddSecurityDefinition("basic", new OpenApiSecurityScheme {
                    Name = "Authorization",
                    Type = SecuritySchemeType.Http,
                    Scheme = "basic",
                    In = ParameterLocation.Header,
                    Description = "Basic Authorization header using the Bearer scheme."
                });

                options.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                          new OpenApiSecurityScheme
                            {
                                Reference = new OpenApiReference
                                {
                                    Type = ReferenceType.SecurityScheme,
                                    Id = "basic"
                                }
                            },
                            Array.Empty<string>()
                    }
                });

                options.CustomSchemaIds(type => type.ToString());

                options.EnableAnnotations();
            });

            services.AddSwaggerGenNewtonsoftSupport();

            // Setup file storage
            switch (Configuration["HostingPlatform"])
            {
                case "Azure": services.AddSingleton<IFileStorage, AzureFileStorage>(); break;
                case "AWS":
                    var awsOptions = Configuration.GetAWSOptions();
                    services.AddDefaultAWSOptions(awsOptions);
                    services.AddAWSService<IAmazonS3>();
                    services.AddSingleton<IFileStorage, AWSFileStorage>();
                    break;
                case "GCP": services.AddSingleton<IFileStorage, GCPFileStorage>(); break;
                case "DevDB": services.AddScoped<IFileStorage, DevDbFileStorage>(); break;
                default:
                {
                    services.AddSingleton<IFileStorage, LocalFileStorage>();
                    Console.WriteLine("WARNING: Using local filesystem for storage as HostingPlatform environment variable not specified or invalid!");
                    break;
                }
            }

            var serviceName = Configuration["Application"] ?? "UACloudLibrary";

            // setup data protection
            switch (Configuration["HostingPlatform"])
            {
                case "Azure": services.AddDataProtection().PersistKeysToAzureBlobStorage(Configuration["BlobStorageConnectionString"], "keys", Configuration["DataProtectionBlobName"]); break;
                case "AWS": services.AddDataProtection().PersistKeysToAWSSystemsManager($"/{serviceName}/DataProtection"); break;
                case "GCP": services.AddDataProtection().PersistKeysToGoogleCloudStorage(Configuration["BlobStorageConnectionString"], "DataProtectionProviderKeys.xml"); break;
                default: services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(Directory.GetCurrentDirectory())); break;
            }

            services.AddHttpContextAccessor();

            services.AddGraphQLServer()
                .AddAuthorization()
                .SetPagingOptions(new HotChocolate.Types.Pagination.PagingOptions {
                    IncludeTotalCount = true,
                    DefaultPageSize = 100,
                    MaxPageSize = 100,
                })
                .AddFiltering(fd => {
                    fd.AddDefaults().BindRuntimeType<UInt32, UnsignedIntOperationFilterInputType>();
                    fd.AddDefaults().BindRuntimeType<UInt32?, UnsignedIntOperationFilterInputType>();
                    fd.AddDefaults().BindRuntimeType<UInt16?, UnsignedShortOperationFilterInputType>();
                })
                .AddSorting()
                .AddQueryType<QueryModel>()
                .AddMutationType<MutationModel>()
                .AddType<CloudLibNodeSetModelType>()
                .BindRuntimeType<UInt32, HotChocolate.Types.UnsignedIntType>()
                .BindRuntimeType<UInt16, HotChocolate.Types.UnsignedShortType>()
                ;

            services.AddScoped<NodeSetModelIndexer>();
            services.AddScoped<NodeSetModelIndexerFactory>();

            services.Configure<IISServerOptions>(options => {
                options.AllowSynchronousIO = true;
            });

            services.Configure<KestrelServerOptions>(options => {
                options.AllowSynchronousIO = true;
            });

            services.AddServerSideBlazor();
        }

        private static async Task OnSignedIn(CookieSignedInContext ctx)
        {
            var userManager = ctx.HttpContext.RequestServices.GetService<UserManager<IdentityUser>>();
            var signInManager = ctx.HttpContext.RequestServices.GetService<SignInManager<IdentityUser>>();

            var id = ctx.Principal.FindFirstValue("http://schemas.microsoft.com/identity/claims/objectidentifier");
            var user = await userManager.FindByIdAsync(id);
            IdentityResult result;
            if (user == null)
            {
                user = new IdentityUser {
                    Id = id,
                    UserName = ctx.Principal.GetDisplayName(),
                };
                result = await userManager.CreateAsync(user);
                if (!result.Succeeded)
                {
                    return;
                }
            }
            await UpdateUserRoles(ctx.Principal, userManager, user);
            await signInManager.SignInAsync(user, isPersistent: false);
        }

        private static async Task UpdateUserRoles(ClaimsPrincipal principal, UserManager<IdentityUser> userManager, IdentityUser user)
        {
            List<string> roles = new();
            foreach (var claim in principal.Claims)
            {
                if (claim.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/role")
                {
                    roles.Add(claim.Value);
                }
            }
            var currentRoles = await userManager.GetRolesAsync(user);
            var rolesToRemove = currentRoles.Except(roles);
            if (rolesToRemove.Any())
            {
                await userManager.RemoveFromRolesAsync(user, rolesToRemove);
            }
            await userManager.AddToRolesAsync(user, roles.Except(currentRoles));
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, AppDbContext appDbContext)
        {
            appDbContext.Database.Migrate();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseSwagger();

            app.UseSwaggerUI(c => {
                c.SwaggerEndpoint("/swagger/v1/swagger.json", "UA Cloud Library REST Service");
            });

            app.UseHttpsRedirection();

            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();

            app.UseAuthorization();

            app.UseGraphQLPlayground(
                "/graphqlui",
                new PlaygroundOptions() {
                    RequestCredentials = RequestCredentials.Include
                });
            app.UseGraphQLGraphiQL("/graphiql");

            app.UseEndpoints(endpoints => {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");

                endpoints.MapRazorPages();
                endpoints.MapBlazorHub();
                endpoints.MapGraphQL()
                    .RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = "BasicAuthentication" })
                    .WithOptions(new GraphQLServerOptions {
                        EnableGetRequests = true,
                        Tool = { Enable = false },
                    });
            });
        }
    }
}
