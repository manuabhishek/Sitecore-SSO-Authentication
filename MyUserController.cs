public class MyUserController : Controller	
{
        public ActionResult Logout()
        {	
            Sitecore.Security.Authentication.AuthenticationManager.Logout();	
            return Redirect("/"); //Mostly irrelevant since redirection is handled from the HandlePostLogoutUrl pipeline.
        }
}