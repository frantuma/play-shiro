package controllers

import org.apache.shiro.SecurityUtils
import play.api._
import play.api.mvc._
import models.User

object Application extends Controller with Authentication {

  def index = Action { implicit request =>
    {
      // demonstrate use of shiro permission handling (no annotations)
      if (!SecurityUtils.getSubject().isPermitted("read")){
        Logger.error("NOT PERMITTED")
      }
      // demonstrate use of shiro authentication (no annotations); this will only be true if url has been excluded,
      // because currently authentication is performed in filter
      if (!SecurityUtils.getSubject().isAuthenticated){
        Logger.error("NOT AUTHENTICATED ")
      }

      // demonstrate use of shiro roles handling (no annotations)
      if (!SecurityUtils.getSubject().hasRole("ROLE_ADMIN")){ // as defined in Global initial data
        Logger.error("NOT ROLE")
      }
      // maintains previous proof of concept level user management/loading
      Ok(views.html.index(User.findAll, Option(SecurityUtils.getSubject.getPrincipal.asInstanceOf[User])))
    }
  }
  
  def logout = Action { implicit request =>
    User.logout()
    Redirect(routes.Application.index).withNewSession.flashing(
      "success" -> "You've been logged out"
    )
  }
  
}


trait Authentication {

  /**
   * Retrieve the connected user email.
   */
  def authToken(request: RequestHeader) = request.session.get("email")

}
