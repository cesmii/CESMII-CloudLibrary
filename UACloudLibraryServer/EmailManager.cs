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

using System;
using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;

namespace Opc.Ua.Cloud.Library
{
    public class EmailManager
    {
        const string EmailTemplate = @"
            <meta http-equiv=""Content-Type"" content=""text/html; charset=utf-8"">
            <p><p>{0} Please <a href=""{1}"">click here</a> to continue.</p>
            <p>If the above link does not work, please copy and paste the link below into your browser’s address bar and press enter:</p>
            <p>{2}</p>
            <p>If you experience difficulty with this site, please reply to this email for help.</p>
            </p>
            <p>The CESMII UA Cloud Library is hosted by <a href='https://www.cesmii.org/'>CESMII</a>, the Clean Energy Smart Manufacturing Institute!
			This Cloud Library contains curated node sets created by CESMII or its members, as well as node sets from the <a href='https://uacloudlibrary.opcfoundation.org/'>OPC Foundation Cloud Library</a>.
			</p>
			";

        //const string EmailTemplate = @"
        //    <meta http-equiv=""Content-Type"" content=""text/html; charset=utf-8"">
        //    <p><img decoding=""async"" class=""alignnone wp-image-1095"" style=""margin: 0px; border: 0px none;"" src=""https://opcfoundation.org/wp-content/uploads/2013/09/OPC_Logo_500x72-300x110.jpg"" alt=""OPC Foundation Logo"" width=""240"" height=""95""></p>
        //    <p><b>The Industrial Interoperability Standard ™</b></p>
        //    <p>&nbsp;</p>
        //    <p><p>{0} Please <a href=""{1}"">click here</a> to continue.</p>
        //    <p>If the above link does not work, please copy and paste the link below into your browser’s address bar and press enter:</p>
        //    <p>{2}</p>
        //    <p>If you experience difficulty with this site, please reply to this email for help.</p>
        //    </p>
        //    <p><strong>OPC Foundation</strong><br>
        //    16101 North 82nd Street, Suite 3B<br>
        //    Scottsdale, Arizona 85260-1868 US<br>
        //    +1 (480) 483-6644<br>
        //    <p style=""text-align: center""><a href=""mailto:unsubscribe@opcfoundation.org?subject=Unsubscribe%20from%20UA%20Cloud%20Library%20Emails&body="">Click here to unsubscribe.</a></p></p>
        //    ";

        private static async Task Send(IEmailSender emailSender, string email, string subject, string action, string url)
        {
            var body = string.Format(
                CultureInfo.InvariantCulture,
                EmailTemplate,
                action,
                HtmlEncoder.Default.Encode(url),
                url);

            await emailSender.SendEmailAsync(
                email,
                subject,
                body).ConfigureAwait(false);
        }

        internal static async Task SendConfirmRegistration(IEmailSender emailSender, string email, string url, bool requireConfirmedAccount)
        {
            StringBuilder sbBody = new StringBuilder();
            sbBody.AppendLine("<h1>Welcome to the CESMII UA Cloud Library</h1>");
            sbBody.AppendLine("<p>Thank you for creating an account on the CESMII UA Cloud Library. ");
            if (requireConfirmedAccount)
            {
                sbBody.AppendLine($"<b>Please confirm your account by <a href='{HtmlEncoder.Default.Encode(url)}'>clicking here</a>.</b></p>".ToString());
            }
            sbBody.AppendLine("<p>The CESMII UA Cloud Library is hosted by <a href='https://www.cesmii.org/'>CESMII</a>, the Clean Energy Smart Manufacturing Institute! This Cloud Library contains curated node sets created by CESMII or its members, as well as node sets from the <a href='https://uacloudlibrary.opcfoundation.org/'>OPC Foundation Cloud Library</a>.</p>");
            sbBody.AppendLine("<p>Sincerely,<br />CESMII DevOps Team</p>");
            await emailSender.SendEmailAsync(
                email,
                "CESMII | Cloud Library | New Account Confirmation",
                sbBody.ToString()).ConfigureAwait(false);

            //notify CESMII dev ops as well
            StringBuilder sbBody2 = new StringBuilder();
            sbBody2.AppendLine("<h1>CESMII UA Cloud Library - New Account Sign Up</h1>");
            sbBody2.AppendLine($"<p>User <b>'{email}'</b> created an account on the CESMII UA Cloud Library.".ToString());
            sbBody2.AppendLine("<p>The CESMII UA Cloud Library is hosted by <a href='https://www.cesmii.org/'>CESMII</a>, the Clean Energy Smart Manufacturing Institute! This Cloud Library contains curated node sets created by CESMII or its members, as well as node sets from the <a href='https://uacloudlibrary.opcfoundation.org/'>OPC Foundation Cloud Library</a>.</p>");
            sbBody2.AppendLine("<p>Sincerely,<br />CESMII DevOps Team</p>");
            await emailSender.SendEmailAsync(
                "devops@cesmii.org",
                "CESMII | Cloud Library | New Account Sign Up",
                sbBody2.ToString()).ConfigureAwait(false);
            //return Send(emailSender, email, "UA Cloud Library - Confirm Your Email", "Please confirm your email to complete registration.", url);
        }

        internal static Task SendConfirmExternalEmail(IEmailSender emailSender, string email, string url)
        {
            return Send(emailSender, email, "CESMII | Cloud Library | Confirm Your Email", "Please confirm your email to complete registration.", url);
            //return Send(emailSender, email, "UA Cloud Library - Confirm Your Email", "Please confirm your email to complete registration.", url);
        }

        internal static Task SendConfirmEmailChange(IEmailSender emailSender, string newEmail, string url)
        {
            return Send(emailSender, newEmail, "CESMII | Cloud Library | Confirm New Email", "Please confirm your email to complete registration.", url);
        }

        internal static Task SendPasswordReset(IEmailSender emailSender, string email, string url)
        {
            StringBuilder sbBody = new StringBuilder();
            sbBody.AppendLine("<h1>Reset Password</h1>");
            sbBody.AppendLine("<p>A request has been made to reset your password in the CESMII Cloud Library.");
            sbBody.AppendLine($"<b>Please click here to <a href='{HtmlEncoder.Default.Encode(url)}'>reset your password</a>.</b></p>".ToString());
            sbBody.AppendLine("<p>If you did not make this request, please contact the <a href='mailto:devops@cesmii.org'>CESMII DevOps Team</a>.</p>");
            sbBody.AppendLine("<p>The CESMII UA Cloud Library is hosted by <a href='https://www.cesmii.org/'>CESMII</a>, the Clean Energy Smart Manufacturing Institute! This Cloud Library contains curated node sets created by CESMII or its members, as well as node sets from the <a href='https://uacloudlibrary.opcfoundation.org/'>OPC Foundation Cloud Library</a>.</p>");
            sbBody.AppendLine("<p>Sincerely,<br />CESMII DevOps Team</p>");
            return emailSender.SendEmailAsync(
                email,
                "CESMII | Cloud Library | Reset Password",
                sbBody.ToString());
            //return Send(emailSender, email, "UA Cloud Library - Reset Password", "We received a request to reset your password.", url);
        }

        internal static Task SendReconfirmEmail(IEmailSender emailSender, string newEmail, string url)
        {
            return Send(emailSender, newEmail, "CESMII | Cloud Library | Verify Your Email", "Please verify your email address.", url);
            //return Send(emailSender, newEmail, "UA Cloud Library - Verify Your Email","Please verify your email address.", url);
        }
    }
}
