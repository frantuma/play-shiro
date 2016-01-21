package models

import org.apache.shiro.SecurityUtils
import org.apache.shiro.authc.{AuthenticationException, UsernamePasswordToken}

import play.api.db._
import play.api.Play.current

import anorm._
import anorm.SqlParser._
import security.Password


/**
 *
 * @author wsargent
 * @since 1/8/12
 */

case class User(email: String, password: String){
  var roles: Seq[String] = Seq()
  var permissions: Seq[String] = Seq()
}

case class Role(name: String){
}

object Role {

  /**
    * Parse a Role from a ResultSet
    */
  val simpleRole = {
    get[String]("user_roles.user_name") ~ get[String]("user_roles.role_name") map { case user_name~role_name => Role(role_name) }
  }


}

object User {

  /**
   * Parse a User from a ResultSet
   */
  val simple = {
    get[String]("user.email") ~ get[String]("user.password") map { case email~password => User(email, password) }
  }


  def findByEmail(email: String): Option[User] = {

    DB.withConnection {
      implicit connection =>
        var optUser = SQL("select * from user where email = {email}").on(
          'email -> email
        ).as(User.simple.singleOpt)

        optUser match {
          case Some(user) => {
            val role = SQL("select * from user_roles where user_name = {email}").on(
              'email -> user.email).as(Role.simpleRole *)

            user.roles = role.map(r => new String(r.name))
            // TODO add permissions
            optUser
          }
          case None => {
            optUser
          }
        }

    }
  }

  def findAll: Seq[User] = {
    DB.withConnection {
      implicit connection =>
        SQL("select * from user").as(User.simple *)
    }
  }

//  def attach(token:String) {
//    SecurityUtils.getSubject.login(token)
//  }

  def authenticate(email: String, password: String): Boolean = {
    // Use shiro to pass through a username password token.
    val token = new UsernamePasswordToken(email, password)
    //token.setRememberMe(true)
    val currentUser = SecurityUtils.getSubject
    try {
      currentUser.login(token)
      true
    } catch {
      case e: AuthenticationException => {
        false
      }
    }
  }

  def logout() {
    SecurityUtils.getSubject.logout()
  }


  def register(email: String, password: String): Boolean = {
    findByEmail(email) match {
      case None => {
        create(User(email, password), Seq(), Seq())
        true
      }
      case _ => false
    }
  }

  def create(user: User, roles: Seq[String], permissions: Seq[String]): User = {
    DB.withConnection {
      implicit connection =>
        SQL(
          """
            insert into user values (
              {email}, {password}
            )
          """
        ).on(
          'email -> user.email,
          'password -> Password.encryptPassword(user.password)
        ).executeUpdate()

        for (role <- roles) {
          SQL(
            """
            insert into user_roles values (
              {user_name}, {role_name}
            )
            """
          ).on(
            'user_name -> user.email,
            'role_name -> role
          ).executeUpdate()
        }
        user
    }
  }


}