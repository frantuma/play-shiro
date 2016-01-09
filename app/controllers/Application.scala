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
      // maintains previous proof of concept level user management/loading
      Ok(views.html.index(User.findAll, currentUserByEmail(SecurityUtils.getSubject.getPrincipal.asInstanceOf[String])))
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

  // not used in this version, where currentUserByEmail is used
  def currentUser(implicit request: RequestHeader) : Option[User] = authToken(request).flatMap { User.findByEmail(_) }

  // same as currentUser but gets email from shiro principal
  def currentUserByEmail(email: String) : Option[User] = User.findByEmail(email)

}
