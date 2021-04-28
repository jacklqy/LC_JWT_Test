using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Zhaoxi.AspNetCore31.AuthDemo.Utility;
using Zhaoxi.AspNetCore31.AuthDemo.Utility.Auth;

namespace Zhaoxi.AspNetCore31.AuthDemo
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews()//反射收集dll-控制器--action--PartManager
                .AddNewtonsoftJson();

            //services.AddAuthorization()
            //services.AddAuthorizationCore();
            //services.AddAuthorizationPolicyEvaluator();

            #region Filter方式
            //services.AddAuthentication()
            //.AddCookie();
            #endregion

            #region Authorize
            //services.AddAuthentication(options =>
            //{
            //    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            //})
            //.AddCookie();
            #endregion

            #region 最基础认证--自定义Handler
            //services.AddAuthenticationCore();
            //services.AddAuthentication().AddCookie();
            //services.AddAuthenticationCore(options => options.AddScheme<CustomHandler>("CustomScheme", "DemoScheme"));
            #endregion

            #region 基于Cookie鉴权
            //services.AddScoped<ITicketStore, MemoryCacheTicketStore>();
            //services.AddMemoryCache();
            //////services.AddDistributedRedisCache(options =>
            //////{
            //////    options.Configuration = "127.0.0.1:6379";
            //////    options.InstanceName = "RedisDistributedSession";
            //////});
            //services.AddAuthentication(options =>
            //{
            //    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;//不能少
            //    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            //    options.DefaultChallengeScheme = "Cookie/Login";
            //})
            //.AddCookie(options =>
            //{
            //    //信息存在服务端--把key写入cookie--类似session
            //    options.SessionStore = services.BuildServiceProvider().GetService<ITicketStore>();
            //    options.Events = new CookieAuthenticationEvents()
            //    {
            //        OnSignedIn = new Func<CookieSignedInContext, Task>(
            //            async context =>
            //            {
            //                Console.WriteLine($"{context.Request.Path} is OnSignedIn");
            //                await Task.CompletedTask;
            //            }),
            //        OnSigningIn = async context =>
            //         {
            //             Console.WriteLine($"{context.Request.Path} is OnSigningIn");
            //             await Task.CompletedTask;
            //         },
            //        OnSigningOut = async context =>
            //        {
            //            Console.WriteLine($"{context.Request.Path} is OnSigningOut");
            //            await Task.CompletedTask;
            //        }
            //    };//扩展事件
            //});

            ////new AuthenticationBuilder().AddCookie()
            #endregion

            #region 基于Cookies授权---角色授权
            //services.AddAuthentication(options =>
            //{
            //    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            //    //不能少,signin signout Authenticate都是基于Scheme
            //    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            //})
            //.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
            //{
            //    options.LoginPath = "/Authorization/Index";
            //    options.AccessDeniedPath = "/Authorization/Index";
            //});
            ////.AddCookie("CustomScheme", options =>
            ////{
            ////    options.LoginPath = "/Authorization/Index";
            ////    options.AccessDeniedPath = "/Authorization/Index";
            ////});
            #endregion

            #region 基于策略授权
            //services.AddAuthentication(options =>
            //{
            //    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;//不能少
            //    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            //})
            //.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
            //{
            //    options.LoginPath = "/Authorization/Index";
            //    options.AccessDeniedPath = "/Authorization/Index";
            //});

            //////定义一个共用的policy
            ////var qqEmailPolicy = new AuthorizationPolicyBuilder().AddRequirements(new QQEmailRequirement()).Build();

            //services.AddAuthorization(options =>
            //{
            //    options.AddPolicy("AdminPolicy",
            //        policyBuilder => policyBuilder
            //        .RequireRole("Admin")//Claim的Role是Admin
            //        .RequireUserName("Eleven")//Claim的Name是Eleven
            //        .RequireClaim(ClaimTypes.Email)//必须有某个Cliam
            //        //.Combine(qqEmailPolicy)
            //        );//内置

            //    options.AddPolicy("UserPolicy",
            //        policyBuilder => policyBuilder.RequireAssertion(context =>
            //        context.User.HasClaim(c => c.Type == ClaimTypes.Role)
            //        && context.User.Claims.First(c => c.Type.Equals(ClaimTypes.Role)).Value == "Admin")
            //   //.Combine(qqEmailPolicy)
            //   );//自定义
            //    //policy层面  没有Requirements


            //    //options.AddPolicy("QQEmail", policyBuilder => policyBuilder.Requirements.Add(new QQEmailRequirement()));
            //    options.AddPolicy("DoubleEmail", policyBuilder => policyBuilder.Requirements.Add(new DoubleEmailRequirement()));
            //});
            //services.AddSingleton<IAuthorizationHandler, ZhaoxiMailHandler>();
            //services.AddSingleton<IAuthorizationHandler, QQMailHandler>();
            #endregion

            #region JWT HS256鉴权授权
            JWTTokenOptions tokenOptions = new JWTTokenOptions();
            Configuration.Bind("JWTTokenOptions", tokenOptions);

            //HS256鉴权-》解析token得到一些基础信息进行鉴权
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)//Scheme
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    //JWT有一些默认的属性，就是给鉴权时就可以筛选了
                    ValidateIssuer = true,//是否验证Issuer
                    ValidateAudience = true,//是否验证Audience
                    ValidateLifetime = true,//是否验证失效时间
                    ValidateIssuerSigningKey = true,//是否验证SecurityKey
                    ValidAudience = tokenOptions.Audience,//
                    ValidIssuer = tokenOptions.Issuer,//Issuer，这两项和前面签发jwt的设置一致
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(tokenOptions.SecurityKey)),//拿到SecurityKey
                    ////jwt封装好的鉴权扩展点--委托
                    //AudienceValidator = (m, n, z) =>
                    //{
                    //    //等同于去扩展了下Audience的校验规则---鉴权
                    //    return m != null && m.FirstOrDefault().Equals(this.Configuration["audience"]);
                    //},
                    //LifetimeValidator = (notBefore, expires, securityToken, validationParameters) =>
                    //{
                    //    return notBefore <= DateTime.Now
                    //    && expires >= DateTime.Now;
                    //    //&& validationParameters
                    //}//自定义校验规则
                };
            });
            //HS256授权-》最终是否能访问页面，有授权决定
            services.AddAuthorization(options =>
            {
                //策略授权
                options.AddPolicy("AdminPolicy",//策略名称
                    policyBuilder => policyBuilder
                    .RequireRole("Admin")//Claim的Role是Admin
                    .RequireUserName("Eleven")//Claim的Name是Eleven
                    .RequireClaim("EMail")//必须有某个Cliam...
                     .RequireClaim("Account")//必须有某个Cliam...
                    //.Combine(qqEmailPolicy)
                    .AddRequirements(new CustomExtendRequirement())
                    );//内置

                //options.AddPolicy("QQEmail", policyBuilder => policyBuilder.Requirements.Add(new QQEmailRequirement()));
                //
                options.AddPolicy("DoubleEmail", policyBuilder => policyBuilder
                .AddRequirements(new CustomExtendRequirement())
                .Requirements.Add(new DoubleEmailRequirement()));
            });
            services.AddSingleton<IAuthorizationHandler, ZhaoxiMailHandler>();
            services.AddSingleton<IAuthorizationHandler, QQMailHandler>();
            services.AddSingleton<IAuthorizationHandler, CustomExtendRequirementHandler>();
            #endregion

            #region JWT RS256鉴权授权
            //#region 读取公钥
            //string path = Path.Combine(Directory.GetCurrentDirectory(), "key.public.json");
            //string key = File.ReadAllText(path);//this.Configuration["SecurityKey"];
            //Console.WriteLine($"KeyPath:{path}");

            //var keyParams = JsonConvert.DeserializeObject<RSAParameters>(key);
            //var credentials = new SigningCredentials(new RsaSecurityKey(keyParams), SecurityAlgorithms.RsaSha256Signature);
            //#endregion

            ////RS256鉴权
            //services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            //.AddJwtBearer(options =>
            //{
            //    options.TokenValidationParameters = new TokenValidationParameters
            //    {
            //        ValidateIssuer = true,//是否验证Issuer
            //        ValidateAudience = true,//是否验证Audience
            //        ValidateLifetime = true,//是否验证失效时间
            //        ValidateIssuerSigningKey = true,//是否验证SecurityKey
            //        ValidAudience = this.Configuration["JWTTokenOptions:Audience"],//Audience
            //        ValidIssuer = this.Configuration["JWTTokenOptions:Issuer"],//Issuer，这两项和前面签发jwt的设置一致
            //        IssuerSigningKey = new RsaSecurityKey(keyParams),
            //        //IssuerSigningKeyValidator = (m, n, z) =>
            //        // {
            //        //     Console.WriteLine("This is IssuerValidator");
            //        //     return true;
            //        // },
            //        //IssuerValidator = (m, n, z) =>
            //        // {
            //        //     Console.WriteLine("This is IssuerValidator");
            //        //     return "http://localhost:5726";
            //        // },
            //        //AudienceValidator = (m, n, z) =>
            //        //{
            //        //    Console.WriteLine("This is AudienceValidator");
            //        //    return true;
            //        //    //return m != null && m.FirstOrDefault().Equals(this.Configuration["JWTTokenOptions:Audience"]);
            //        //},//自定义校验规则，可以新登录后将之前的无效
            //    };
            //});
            ////RS256授权-》最终是否能访问页面，有授权决定
            //services.AddAuthorization(options =>
            //{
            //    //策略授权
            //    options.AddPolicy("AdminPolicy",//策略名称
            //        policyBuilder => policyBuilder
            //        .RequireRole("Admin")//Claim的Role是Admin
            //        .RequireUserName("Eleven")//Claim的Name是Eleven
            //        .RequireClaim("EMail")//必须有某个Cliam...
            //         .RequireClaim("Account")//必须有某个Cliam...
            //        //.Combine(qqEmailPolicy)
            //        .AddRequirements(new CustomExtendRequirement())
            //        );//内置

            //    //options.AddPolicy("QQEmail", policyBuilder => policyBuilder.Requirements.Add(new QQEmailRequirement()));
            //    //
            //    options.AddPolicy("DoubleEmail", policyBuilder => policyBuilder
            //    .AddRequirements(new CustomExtendRequirement())
            //    .Requirements.Add(new DoubleEmailRequirement()));
            //});
            //services.AddSingleton<IAuthorizationHandler, ZhaoxiMailHandler>();
            //services.AddSingleton<IAuthorizationHandler, QQMailHandler>();
            //services.AddSingleton<IAuthorizationHandler, CustomExtendRequirementHandler>();
            #endregion
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles(new StaticFileOptions()
            {
                FileProvider = new PhysicalFileProvider(Path.Combine(Directory.GetCurrentDirectory(), @"wwwroot"))
            });

            app.UseRouting();

            #region 基于CookieAuthentication
            //app.UseAuthentication();//鉴权
            #endregion

            #region  JWT
            app.UseAuthentication();//鉴权：解析信息--就是读取token，解密token
            #endregion

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
