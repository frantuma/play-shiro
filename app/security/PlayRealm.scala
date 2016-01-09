package security

import org.apache.shiro.realm.AuthorizingRealm
import org.apache.shiro.authc._
import org.apache.shiro.authc.credential._
import org.apache.shiro.subject._
import org.apache.shiro.authz._

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

    // retrieve the 'real' user password
    val password = passwordOf(username)

    checkNotNull(password, "No account found for user [" + username + "]")

    // return the 'real' info for username, security manager is then responsible
    // for checking the token against the provided info
    new SimpleAuthenticationInfo(username, password, getName)
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

  private def passwordOf(username:String) : String = {
    User.findByEmail(username) match {
      case Some(user) => user.password
      case None => null
    }
  }

  def doGetAuthorizationInfo(principals: PrincipalCollection):AuthorizationInfo = {
    //checkNotNull(principals, "PrincipalCollection method argument cannot be null.")
    import scala.collection.JavaConversions._
    val username = principals.getPrimaryPrincipal.asInstanceOf[String]
    val info = new SimpleAuthorizationInfo(rolesOf(username))
    info.setStringPermissions(permissionsOf(username))
    info
  }

  private def permissionsOf(username:String):Set[String] = {
    username match {
      //case "admin@example.org" => Set("user:create,read,update,delete")
      case "admin@example.com" => {
        Set("read")
      }
      case _ => {
        Set.empty
      }
    }
  }

  private def rolesOf(username:String):Set[String] = {
    username match {
      case "admin@example.org" => Set("admin")
      case _ => Set.empty
    }
  }

  private def checkNotNull(reference: String, message: String) {
    if (reference == null) {
      throw new AuthenticationException(message)
    }
  }
}
