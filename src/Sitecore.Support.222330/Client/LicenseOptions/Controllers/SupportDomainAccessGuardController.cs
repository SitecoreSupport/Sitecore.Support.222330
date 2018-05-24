extern alias LicenseOptions;
using Sitecore.Diagnostics;
using LicenseOptions::Sitecore.Client.LicenseOptions.Controllers.Model;
using LicenseOptions::Sitecore.Client.LicenseOptions;
using Sitecore.Web;
using Sitecore.Web.Authentication;
using System.Linq;
using System.Net;
using System.Web.Mvc;
using System.Text;
using Sitecore.Configuration;

namespace Sitecore.Support.Client.LicenseOptions.Controllers
{
  public class SupportDomainAccessGuardController : Controller
  {
    [HttpPost]
    public JsonResult KickUser()
    {
      if (!Context.User.IsAuthenticated)
      {
        Response.StatusCode = (int)HttpStatusCode.Unauthorized;
        return ErrorResultService.GetErrorMessageResult("Unauthorized");
      }

      string sessionId = Request["sid"];
      if (string.IsNullOrEmpty(sessionId))
      {
        Response.StatusCode = (int)HttpStatusCode.BadRequest;
        return ErrorResultService.GetErrorMessageResult("Cannot kick user. No session ID is specified.");
      }

      DomainAccessGuard.Session session = DomainAccessGuard.Sessions.FirstOrDefault(s => s.SessionID == sessionId);

      if (!UserIsAllowedToKickSession(session))
      {
        Response.StatusCode = (int)HttpStatusCode.Unauthorized;
        return ErrorResultService.GetErrorMessageResult(("Unauthorized"));
      }

      if (session != null)
      {
        Log.Audit(this, "Kick user: {0} (session: {1})", session.UserName, sessionId);
      }
      else
      {
        Log.Audit(this, "Kick session: {0}", sessionId);
      }

      DomainAccessGuard.Kick(sessionId);
      return GetResult(new ResultMessage
      {
        Status = ResultStatus.Success,
        Message = WebUtil.GetFullUrl(new LicenseOptions::Sitecore.Client.LicenseOptions.StartUrlManager().GetStartUrl(Context.User))
      });
    }
    protected JsonResult GetResult(object data)
    {
      return new JsonResult
      {
        ContentEncoding = Encoding.UTF8,
        ContentType = "application/json",
        Data = data,
        JsonRequestBehavior = JsonRequestBehavior.AllowGet
      };
    }
    protected bool UserIsAllowedToKickSession(DomainAccessGuard.Session guardSession)
    {
      if (!Context.IsAdministrator && !Settings.AllowLogoutOfAllUsers)
      {
        return guardSession.UserName == Context.User.Name;
      }
      return true;
    }
  }
}