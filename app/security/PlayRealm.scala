package security

import org.apache.shiro.realm.AuthorizingRealm
import org.apache.shiro.authc._
import org.apache.shiro.authc.credential._
import org.apache.shiro.subject._
import org.apache.shiro.authz._

import scala.collection.JavaConverters._
import models.User

/**
 * Custom realm, with thanks to
 * <a href="https://github.com/Arnauld/scalaadin/wiki/Authentication:-Vaadin+Shiro">the Vaadin Shiro integration</a>.
 *
 * @author wsargent
 * @since 1/8/12
 */
class PlayRealm extends AuthorizingRealm {

  override protected def doGetAuthenticationInfo(token: AuthenticationToken): AuthenticationInfo = {

    val upToken = token.asInstanceOf[UsernamePasswordToken]

    val username = upToken.getUsername
    checkNotNull(username, "Null usernames are not allowed by this realm.")

    // retrieve the user
    val user = User.findByEmail(username)
    checkNotNull(user.getOrElse(null), "No account found for user [" + username + "]")
    // retrieve the 'real' user password
    val password = passwordOf(user)
    // return the 'real' info for username, security manager is then responsible
    // for checking the token against the provided info
    new SimpleAuthenticationInfo(user.get, password, getName)
  }

  override def getCredentialsMatcher = new CredentialsMatcher() {
    // Note that the password is salted, and so all password comparisons
    // MUST be done through the password encryptor.
    def doCredentialsMatch(token: AuthenticationToken, info: AuthenticationInfo) = {
      val message = new String(token.getCredentials.asInstanceOf[Array[Char]])
      val digest = info.getCredentials.toString
      val result = Password.checkPassword(message, digest)
      result
    }
  }

  private def passwordOf(user:Option[User]) : String = {
    user match {
      case Some(aUser) => aUser.password
      case None => null
    }
  }

  def doGetAuthorizationInfo(principals: PrincipalCollection):AuthorizationInfo = {
    //checkNotNull(principals, "PrincipalCollection method argument cannot be null.")
    val user = principals.getPrimaryPrincipal.asInstanceOf[User]
    val info = new SimpleAuthorizationInfo(user.roles.toSet.asJava)
    //info.setStringPermissions(permissionsOf(user)) TODO
    info
  }

  private def rolesOf(username:String):Set[String] = {
    username match {
      case "admin@example.org" => Set("admin")
      case _ => Set.empty
    }
  }

  private def checkNotNull(reference: Any, message: String) {
    if (reference == null) {
      throw new AuthenticationException(message)
    }
  }
}
