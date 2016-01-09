package security

import com.typesafe.config.ConfigValueType

import models.User
import org.apache.commons.codec.binary.Base64
import org.apache.shiro.SecurityUtils

import play.api.Configuration
import play.api.http.HeaderNames.AUTHORIZATION
import play.api.http.HeaderNames.WWW_AUTHENTICATE
import play.api.libs.Crypto
import play.api.libs.concurrent.Execution.Implicits.defaultContext
import play.api.mvc.Cookie
import play.api.mvc.Filter
import play.api.mvc.RequestHeader
import play.api.mvc.Result
import play.api.mvc.Results.Unauthorized

import scala.collection.JavaConverters._
import scala.concurrent.Future

/**
  * based on https://github.com/Kaliber/play-basic-authentication-filter/blob/master/src/test/scala/net/kaliber/basicAuthentication/BasicAuthenticationFilterSpec.scala
  * adapted to use Shiro
  *
  * @param configurationFactory
  */
class BasicAuthenticationFilter(configurationFactory: => BasicAuthenticationFilterConfiguration) extends Filter {

  def apply(next: RequestHeader => Future[Result])(requestHeader: RequestHeader): Future[Result] =
    if (configuration.enabled && isNotExcluded(requestHeader))
      checkAuthentication(requestHeader, next)
    else next(requestHeader)

  private def isNotExcluded(requestHeader: RequestHeader): Boolean =
    !configuration.excluded.exists( requestHeader.path matches _ )

  private def checkAuthentication(requestHeader: RequestHeader, next: RequestHeader => Future[Result]): Future[Result] = {
    SecurityUtils.getSubject.logout()
    if (isAuthorized(requestHeader)){
      addCookie(next(requestHeader), buildCookieValue(requestHeader))
    }
    else unauthorizedResult
  }

  private def isAuthorized(requestHeader: RequestHeader) = {
    // get username from auth or cookie
    val header = requestHeader.headers.get(AUTHORIZATION).getOrElse("")
    var authorizedByHeader = false
    if (header.startsWith("Basic")){
      val encoded = header.split("\\s+")(1)
      val decoded = new String(Base64.decodeBase64(encoded.getBytes()))
      val user = decoded.split("\\:")(0)
      val pass = decoded.split("\\:")(1)
      // check with shiro
      authorizedByHeader = User.authenticate(user, pass)
    }
    // for the moment don't handle cookies
    val authorizedByCookie = false
    authorizedByHeader || authorizedByCookie
  }

  private def buildCookieValue(requestHeader: RequestHeader): String = {
    // assumes isAuthorized has been called, therefore header or cookie populated
    val header = requestHeader.headers.get(AUTHORIZATION).getOrElse("")
    if (header.startsWith("Basic")){
      val encoded = header.split("\\s+")(1)
      val decoded = new String(Base64.decodeBase64(encoded.getBytes()))
      val user = decoded.split("\\:")(0)
      val pass = decoded.split("\\:")(1)
      return user + "_" + Crypto.sign(user + pass)
    } else {
      return requestHeader.cookies.get(COOKIE_NAME).get.value
    }

  }

  private def addCookie(result: Future[Result], cookieValue: String) =
    result.map(_.withCookies(Cookie(COOKIE_NAME, cookieValue)))

  private lazy val configuration = configurationFactory

  private lazy val unauthorizedResult =
    Future successful Unauthorized.withHeaders(WWW_AUTHENTICATE -> "Application")

  private lazy val COOKIE_NAME = "play-basic-authentication-filter"

  private def basic(content: String) = s"Basic $content"
}

object BasicAuthenticationFilter {
  def apply() = new BasicAuthenticationFilter(
    BasicAuthenticationFilterConfiguration.parse(
      play.api.Play.current.configuration
    )
  )

  def apply(configuration: => Configuration) = new BasicAuthenticationFilter(
    BasicAuthenticationFilterConfiguration parse configuration
  )
}

case class BasicAuthenticationFilterConfiguration(
                                                   enabled: Boolean,
                                                   excluded: Set[String])

object BasicAuthenticationFilterConfiguration {

  def parse(configuration: Configuration) = {

    val root = "basicAuthentication."
    def boolean(key: String) = configuration.getBoolean(root + key)
    def string(key: String) = configuration.getString(root + key)
    def seq(key: String) =
      Option(configuration.underlying getValue (root + key)).map { value =>
        value.valueType match {
          case ConfigValueType.LIST => value.unwrapped.asInstanceOf[java.util.List[String]].asScala
          case ConfigValueType.STRING => Seq(value.unwrapped.asInstanceOf[String])
          case _ => sys.error(s"Unexpected value at `${root + key}`, expected STRING or LIST")
        }
      }

    val enabled = boolean("enabled").getOrElse(true)

    val excluded = configuration.getStringSeq(root + "excluded")
      .getOrElse(Seq.empty)
      .toSet

    BasicAuthenticationFilterConfiguration(
      enabled,
      excluded
    )
  }
}
