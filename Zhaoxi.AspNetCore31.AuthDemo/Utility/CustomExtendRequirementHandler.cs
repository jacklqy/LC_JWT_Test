﻿using Microsoft.AspNetCore.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Zhaoxi.AspNetCore31.AuthDemo.Utility
{

    public class CustomExtendRequirement : IAuthorizationRequirement
    {
    }
    public class CustomExtendRequirementHandler : AuthorizationHandler<CustomExtendRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, CustomExtendRequirement requirement)
        {
            ////这里啥东西都拿到了，就可以做一系列想做的校验，比如redis里面校验
            //context.User.Identities.First().Claims

            //var jti = context.User.FindFirst("jti")?.Value;// 检查 Jti 是否存在

            bool tokenExists = true;
            if (tokenExists)
            {
                context.Fail();
            }
            else
            {
                context.Succeed(requirement); // 显式的声明验证成功
            }
            return Task.CompletedTask;
        }
    }
}
